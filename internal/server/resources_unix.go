//go:build unix

package server

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

func init() {
	prepareResourceLimits = prepareResourceLimitsUnix
}

func prepareResourceLimitsUnix(concurrent uint32) error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("read file descriptor limit: %w", err)
	}
	// A TCP tunnel consumes two descriptors. SOCKS5 UDP associations can use a
	// TCP control connection plus inbound, preferred, and fallback UDP sockets,
	// so reserve four descriptors per configured client plus process headroom.
	required := uint64(concurrent)*4 + 4096
	hardLimit := uint64(limit.Max)
	softLimit := uint64(limit.Cur)
	if hardLimit < required {
		return fmt.Errorf(
			"file descriptor hard limit %d is below the %d required for %d concurrent connections",
			hardLimit,
			required,
			concurrent,
		)
	}
	if softLimit >= required {
		return nil
	}
	limit.Cur = limit.Max
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("raise file descriptor limit from %d to %d: %w", softLimit, hardLimit, err)
	}
	slog.Info("Raised file descriptor limit", "from", softLimit, "to", hardLimit)
	return nil
}
