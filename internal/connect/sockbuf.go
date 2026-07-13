package connect

import "net"

// VerifyUDPBufferTuning applies the requested buffer size to a throwaway UDP
// socket and reports the size the kernel actually granted, so startup can warn
// about silent clamping. clamped is true when the granted size is below the
// request (on Linux this happens when the request exceeds net.core.rmem_max and
// the process lacks CAP_NET_ADMIN). ok is false when the granted size cannot be
// read on this platform, in which case applied and clamped are meaningless.
func VerifyUDPBufferTuning(requested int) (applied int, clamped, ok bool) {
	if requested <= 0 {
		return 0, false, false
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		conn, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
		if err != nil {
			return 0, false, false
		}
	}
	defer conn.Close()

	TuneUDPBuffers(conn, requested)
	applied, ok = currentUDPRecvBuffer(conn)
	if !ok {
		return 0, false, false
	}
	return applied, applied < requested, true
}
