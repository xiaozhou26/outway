package proto

import "fmt"

// Command is a SOCKS5 command code.
type Command uint8

const (
	CmdConnect      Command = 0x01
	CmdBind         Command = 0x02
	CmdUDPAssociate Command = 0x03
)

// ParseCommand parses a command byte.
func ParseCommand(b uint8) (Command, error) {
	switch b {
	case 0x01:
		return CmdConnect, nil
	case 0x02:
		return CmdBind, nil
	case 0x03:
		return CmdUDPAssociate, nil
	default:
		return 0, fmt.Errorf("unsupported command code %#x", b)
	}
}

// Byte returns the wire byte for the command.
func (c Command) Byte() uint8 { return uint8(c) }
