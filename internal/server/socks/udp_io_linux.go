//go:build linux

package socks

import (
	"errors"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type linuxUDPBatchReader struct {
	runtime       *udpRuntime
	conn          *net.UDPConn
	offset        int
	limit         int
	v4            *ipv4.PacketConn
	v6            *ipv6.PacketConn
	v4msgs        []ipv4.Message
	v6msgs        []ipv6.Message
	bufs          [][]byte
	packets       []udpReadPacket
	batchDisabled bool
	gro           bool
	groPackets    []udpReadPacket
	groOOB        []byte
}

func newUDPBatchReader(conn *net.UDPConn, runtime *udpRuntime, offset, limit int) udpBatchReader {
	r := &linuxUDPBatchReader{
		runtime: runtime,
		conn:    conn,
		offset:  offset,
		limit:   limit,
		bufs:    make([][]byte, runtime.config.BatchSize),
		packets: make([]udpReadPacket, runtime.config.BatchSize),
	}
	if runtime.config.GRO && udpGROSupported() && enableUDPGRO(conn) == nil {
		r.gro = true
		r.groPackets = make([]udpReadPacket, groMaxSegments)
		r.groOOB = make([]byte, 128)
		return r
	}
	if conn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		r.v4 = ipv4.NewPacketConn(conn)
		r.v4msgs = make([]ipv4.Message, runtime.config.BatchSize-1)
		for i := range r.v4msgs {
			r.v4msgs[i].Buffers = make([][]byte, 1)
		}
	} else {
		r.v6 = ipv6.NewPacketConn(conn)
		r.v6msgs = make([]ipv6.Message, runtime.config.BatchSize-1)
		for i := range r.v6msgs {
			r.v6msgs[i].Buffers = make([][]byte, 1)
		}
	}
	return r
}

func (r *linuxUDPBatchReader) Read() ([]udpReadPacket, error) {
	if r.gro {
		return r.readGRO()
	}
	return r.readBatch()
}

// readGRO performs one blocking read on a UDP_GRO socket. When the kernel
// coalesced several same-flow, same-size datagrams into the buffer it splits
// them back into individual packets: the first reuses the read buffer, the rest
// are copied into their own pooled buffers so the downstream one-buffer-per-
// packet lifecycle is preserved. A larger recvmmsg drain is unnecessary because
// GRO already coalesces the flow into this single read.
func (r *linuxUDPBatchReader) readGRO() ([]udpReadPacket, error) {
	buffer := r.runtime.getBuffer()
	// GRO coalesces several datagrams into one read, so use the whole pooled
	// buffer (bounded by MaxPacketSize+header) rather than a single-datagram
	// slice; the per-segment size is validated against the limit below.
	n, oobn, flags, addr, err := r.conn.ReadMsgUDP(buffer[r.offset:], r.groOOB)
	if err != nil {
		r.runtime.putBuffer(buffer)
		return nil, err
	}
	src := addr.AddrPort()
	if flags&unix.MSG_TRUNC != 0 {
		r.groPackets[0] = udpReadPacket{buffer: buffer, n: n, addr: src, truncated: true}
		return r.groPackets[:1], nil
	}

	segmentSize := parseGROSize(r.groOOB[:oobn])
	if segmentSize <= 0 || segmentSize > r.limit || n <= segmentSize {
		r.groPackets[0] = udpReadPacket{buffer: buffer, n: n, addr: src, truncated: n > r.limit}
		return r.groPackets[:1], nil
	}

	fullSegments := n / segmentSize
	remainder := n % segmentSize
	segments := fullSegments
	if remainder > 0 {
		segments++
	}
	if segments > groMaxSegments {
		segments = groMaxSegments
		r.runtime.metrics.groTruncatedReads.Add(1)
	}
	r.runtime.metrics.groCoalescedReads.Add(1)

	// The first segment already sits at the read offset.
	r.groPackets[0] = udpReadPacket{buffer: buffer, n: segmentSize, addr: src}
	for i := 1; i < segments; i++ {
		segmentLen := segmentSize
		if i == fullSegments {
			segmentLen = remainder
		}
		copied := r.runtime.getBuffer()
		start := r.offset + i*segmentSize
		copy(copied[r.offset:r.offset+segmentLen], buffer[start:start+segmentLen])
		r.groPackets[i] = udpReadPacket{buffer: copied, n: segmentLen, addr: src}
	}
	return r.groPackets[:segments], nil
}

func (r *linuxUDPBatchReader) readBatch() ([]udpReadPacket, error) {
	// Block with a single buffer so idle associations do not pin an entire
	// batch. Once one datagram arrives, opportunistically drain the socket with
	// non-blocking recvmmsg into the remaining batch slots.
	first := r.runtime.getBuffer()
	n, _, flags, addr, err := r.conn.ReadMsgUDP(first[r.offset:r.offset+r.limit+1], nil)
	if err != nil {
		r.runtime.putBuffer(first)
		return nil, err
	}
	r.bufs[0] = first
	r.packets[0] = udpReadPacket{
		buffer:    first,
		n:         n,
		addr:      addr.AddrPort(),
		truncated: flags&unix.MSG_TRUNC != 0 || n > r.limit,
	}
	if r.runtime.config.BatchSize == 1 {
		return r.packets[:1], nil
	}
	if r.batchDisabled {
		return r.packets[:1], nil
	}
	extraBuffers := 0
	for i := 1; i < len(r.bufs); i++ {
		if !r.runtime.tryAcquireBatchBuffer() {
			break
		}
		buf := r.runtime.getBuffer()
		r.bufs[i] = buf
		extraBuffers++
		if r.v4 != nil {
			r.v4msgs[i-1].Buffers[0] = buf[r.offset : r.offset+r.limit+1]
		} else {
			r.v6msgs[i-1].Buffers[0] = buf[r.offset : r.offset+r.limit+1]
		}
	}
	if extraBuffers == 0 {
		return r.packets[:1], nil
	}
	var drained int
	if r.v4 != nil {
		drained, err = r.v4.ReadBatch(r.v4msgs[:extraBuffers], unix.MSG_DONTWAIT)
	} else {
		drained, err = r.v6.ReadBatch(r.v6msgs[:extraBuffers], unix.MSG_DONTWAIT)
	}
	if err != nil {
		for i := 1; i <= extraBuffers; i++ {
			r.runtime.releaseBuffer(r.bufs[i], true)
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return r.packets[:1], nil
		}
		// The blocking scalar read already succeeded. Preserve that datagram and
		// fall back to the scalar path for this iteration if opportunistic drain
		// is unavailable.
		r.batchDisabled = true
		r.runtime.metrics.batchFallbacks.Add(1)
		return r.packets[:1], nil
	}
	for i := range drained {
		var messageN, flags int
		var addr net.Addr
		if r.v4 != nil {
			messageN, flags, addr = r.v4msgs[i].N, r.v4msgs[i].Flags, r.v4msgs[i].Addr
		} else {
			messageN, flags, addr = r.v6msgs[i].N, r.v6msgs[i].Flags, r.v6msgs[i].Addr
		}
		addrPort, _ := udpAddrPort(addr)
		r.packets[i+1] = udpReadPacket{buffer: r.bufs[i+1], n: messageN, addr: addrPort, truncated: flags&unix.MSG_TRUNC != 0 || messageN > r.limit, batchSlot: true}
	}
	for i := drained + 1; i <= extraBuffers; i++ {
		r.runtime.releaseBuffer(r.bufs[i], true)
	}
	return r.packets[:drained+1], nil
}

type linuxUDPBatchWriter struct {
	v4     *ipv4.PacketConn
	v6     *ipv6.PacketConn
	v4msgs []ipv4.Message
	v6msgs []ipv6.Message
}

func newUDPBatchWriter(conn *net.UDPConn, batchSize int) udpBatchWriter {
	w := &linuxUDPBatchWriter{}
	if conn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		w.v4 = ipv4.NewPacketConn(conn)
		w.v4msgs = make([]ipv4.Message, batchSize)
		for i := range w.v4msgs {
			w.v4msgs[i].Buffers = make([][]byte, 1)
		}
	} else {
		w.v6 = ipv6.NewPacketConn(conn)
		w.v6msgs = make([]ipv6.Message, batchSize)
		for i := range w.v6msgs {
			w.v6msgs[i].Buffers = make([][]byte, 1)
		}
	}
	return w
}

func (w *linuxUDPBatchWriter) Write(packets []udpWritePacket) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if w.v4 != nil {
		messages := w.v4msgs[:len(packets)]
		for i, packet := range packets {
			messages[i].Buffers[0] = packet.buffer
			messages[i].Addr = net.UDPAddrFromAddrPort(packet.addr)
		}
		return writeIPv4Messages(w.v4, messages)
	}
	messages := w.v6msgs[:len(packets)]
	for i, packet := range packets {
		messages[i].Buffers[0] = packet.buffer
		messages[i].Addr = net.UDPAddrFromAddrPort(packet.addr)
	}
	return writeIPv6Messages(w.v6, messages)
}

func writeIPv4Messages(conn *ipv4.PacketConn, messages []ipv4.Message) (int, error) {
	total := 0
	for total < len(messages) {
		n, err := conn.WriteBatch(messages[total:], 0)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
	return total, nil
}

func writeIPv6Messages(conn *ipv6.PacketConn, messages []ipv6.Message) (int, error) {
	total := 0
	for total < len(messages) {
		n, err := conn.WriteBatch(messages[total:], 0)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, nil
		}
	}
	return total, nil
}
