package handshake

import "fmt"

// Method is a SOCKS5 authentication method.
type Method uint8

const (
	MethodNoAuth              Method = 0x00
	MethodGssApi              Method = 0x01
	MethodPassword            Method = 0x02
	MethodNoAcceptableMethods Method = 0xff
)

// MethodFromByte converts a wire byte to a Method.
func MethodFromByte(b uint8) Method {
	switch b {
	case 0x00:
		return MethodNoAuth
	case 0x01:
		return MethodGssApi
	case 0x02:
		return MethodPassword
	case 0xff:
		return MethodNoAcceptableMethods
	default:
		if b >= 0x03 && b <= 0x7f {
			return Method(b) // IANA reserved
		}
		return Method(b) // private
	}
}

// Byte returns the wire byte for the method.
func (m Method) Byte() uint8 { return uint8(m) }

// String returns the method name.
func (m Method) String() string {
	switch m {
	case MethodNoAuth:
		return "NoAuth"
	case MethodGssApi:
		return "GssApi"
	case MethodPassword:
		return "UserPass"
	case MethodNoAcceptableMethods:
		return "NoAcceptableMethods"
	default:
		return fmt.Sprintf("Method(%#x)", uint8(m))
	}
}
