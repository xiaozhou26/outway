// Configuration file support: LoadFile parses an optional YAML file whose
// values seed the CLI flag variables before cobra parses the command line, so
// a flag given explicitly always wins over the file.

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// FileConfig mirrors the CLI flags. Every field is a pointer so that an
// absent key can be distinguished from a zero value: only present keys are
// applied. Field names follow the long flag names; the UDP flags nest under
// the "udp" key.
type FileConfig struct {
	Log             *string `yaml:"log"`
	Bind            *string `yaml:"bind"`
	Concurrent      *uint32 `yaml:"concurrent"`
	Workers         *int    `yaml:"workers"`
	CIDR            *string `yaml:"cidr"`
	CIDRRange       *uint8  `yaml:"cidr-range"`
	Fallback        *string `yaml:"fallback"`
	ConnectTimeout  *uint64 `yaml:"connect-timeout"`
	TCPUserTimeout  *uint64 `yaml:"tcp-user-timeout"`
	ReuseAddr       *bool   `yaml:"reuseaddr"`
	MaxPendingDials *int    `yaml:"max-pending-dials"`
	ReusePort       *bool   `yaml:"reuse-port"`
	Diagnostics     *string `yaml:"diagnostics"`
	Username        *string `yaml:"username"`
	Password        *string `yaml:"password"`
	TLSCert         *string `yaml:"tls-cert"`
	TLSKey          *string `yaml:"tls-key"`
	UDP             *FileUDPConfig
}

// FileUDPConfig mirrors the --udp-* flags under the "udp" config-file key.
type FileUDPConfig struct {
	MaxPacketSize              *int    `yaml:"max-packet-size"`
	BatchSize                  *int    `yaml:"batch-size"`
	BatchBufferBudget          *int    `yaml:"batch-buffer-budget"`
	SendQueueSize              *int    `yaml:"send-queue"`
	SendWorkers                *int    `yaml:"send-workers"`
	SocketBufferBytes          *int    `yaml:"socket-buffer"`
	GSO                        *bool   `yaml:"gso"`
	GRO                        *bool   `yaml:"gro"`
	MaxAssociations            *uint32 `yaml:"associations"`
	MetricsIntervalSecs        *uint64 `yaml:"metrics-interval"`
	AssociationIdleTimeoutSecs *uint64 `yaml:"association-idle-timeout"`
}

// LoadFile reads and strictly parses the YAML config at path. Unknown keys are
// rejected so a typoed setting fails at startup instead of being silently
// ignored. An empty file yields a nil config.
func LoadFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var fc FileConfig
	if err := dec.Decode(&fc); err != nil {
		// A file with only comments/whitespace has no documents.
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("parse config file %s: %w", path, err)
	}
	return &fc, nil
}
