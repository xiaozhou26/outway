package proto

import "fmt"

// Reply is a SOCKS5 reply code.
type Reply uint8

const (
	ReplySucceeded              Reply = 0x00
	ReplyGeneralFailure         Reply = 0x01
	ReplyConnectionNotAllowed   Reply = 0x02
	ReplyNetworkUnreachable     Reply = 0x03
	ReplyHostUnreachable        Reply = 0x04
	ReplyConnectionRefused      Reply = 0x05
	ReplyTtlExpired             Reply = 0x06
	ReplyCommandNotSupported    Reply = 0x07
	ReplyAddressTypeNotSupported Reply = 0x08
)

// ParseReply parses a reply byte.
func ParseReply(b uint8) (Reply, error) {
	switch b {
	case 0x00:
		return ReplySucceeded, nil
	case 0x01:
		return ReplyGeneralFailure, nil
	case 0x02:
		return ReplyConnectionNotAllowed, nil
	case 0x03:
		return ReplyNetworkUnreachable, nil
	case 0x04:
		return ReplyHostUnreachable, nil
	case 0x05:
		return ReplyConnectionRefused, nil
	case 0x06:
		return ReplyTtlExpired, nil
	case 0x07:
		return ReplyCommandNotSupported, nil
	case 0x08:
		return ReplyAddressTypeNotSupported, nil
	default:
		return 0, fmt.Errorf("unsupported reply code %#x", b)
	}
}

// Byte returns the wire byte for the reply.
func (r Reply) Byte() uint8 { return uint8(r) }

// String returns the reply name.
func (r Reply) String() string {
	switch r {
	case ReplySucceeded:
		return "Succeeded"
	case ReplyGeneralFailure:
		return "GeneralFailure"
	case ReplyConnectionNotAllowed:
		return "ConnectionNotAllowed"
	case ReplyNetworkUnreachable:
		return "NetworkUnreachable"
	case ReplyHostUnreachable:
		return "HostUnreachable"
	case ReplyConnectionRefused:
		return "ConnectionRefused"
	case ReplyTtlExpired:
		return "TtlExpired"
	case ReplyCommandNotSupported:
		return "CommandNotSupported"
	case ReplyAddressTypeNotSupported:
		return "AddressTypeNotSupported"
	default:
		return fmt.Sprintf("Reply(%#x)", uint8(r))
	}
}
