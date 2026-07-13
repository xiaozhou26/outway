//go:build !linux

package socks

import (
	"net"
	"net/netip"
)

type genericUDPBatchReader struct {
	runtime *udpRuntime
	conn    *net.UDPConn
	offset  int
	limit   int
	packet  [1]udpReadPacket
}

func newUDPBatchReader(conn *net.UDPConn, runtime *udpRuntime, offset, limit int) udpBatchReader {
	return &genericUDPBatchReader{runtime: runtime, conn: conn, offset: offset, limit: limit}
}

func (r *genericUDPBatchReader) Read() ([]udpReadPacket, error) {
	buf := r.runtime.getBuffer()
	n, _, flags, addr, err := r.conn.ReadMsgUDP(buf[r.offset:r.offset+r.limit+1], nil)
	errorTruncated := udpReadErrorTruncated(err)
	if err != nil && !errorTruncated {
		r.runtime.putBuffer(buf)
		return nil, err
	}
	var addrPort netip.AddrPort
	if addr != nil {
		addrPort = addr.AddrPort()
	}
	r.packet[0] = udpReadPacket{
		buffer:    buf,
		n:         n,
		addr:      addrPort,
		truncated: errorTruncated || udpMessageTruncated(flags) || n > r.limit,
	}
	return r.packet[:], nil
}

type genericUDPBatchWriter struct{ conn *net.UDPConn }

func newUDPBatchWriter(conn *net.UDPConn, _ int) udpBatchWriter {
	return &genericUDPBatchWriter{conn: conn}
}

func (w *genericUDPBatchWriter) Write(packets []udpWritePacket) (int, error) {
	for index, packet := range packets {
		if _, err := w.conn.WriteToUDP(packet.buffer, net.UDPAddrFromAddrPort(packet.addr)); err != nil {
			return index, err
		}
	}
	return len(packets), nil
}
