//go:build unix

package server

import (
	"fmt"
	"log/slog"

	"github.com/xiaozhou26/outway/internal/config"
	"golang.org/x/sys/unix"
)

func init() {
	prepareResourceLimits = prepareResourceLimitsUnix
}

func prepareResourceLimitsUnix(args config.BootArgs) error {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("read file descriptor limit: %w", err)
	}
	// Every active connection may consume two descriptors. A UDP association
	// can consume two additional UDP descriptors (inbound plus dual-stack
	// outbound), so add that budget only for protocols which support SOCKS5.
	required := uint64(args.Concurrent)*2 + 4096
	if args.Proxy.Kind == config.ProxySocks5 || args.Proxy.Kind == config.ProxyAuto {
		associations := args.UDP.MaxAssociations
		if associations == 0 {
			associations = args.Concurrent
		}
		required += uint64(associations) * 2
	}
	hardLimit := uint64(limit.Max)
	softLimit := uint64(limit.Cur)
	if hardLimit < required {
		return fmt.Errorf(
			"file descriptor hard limit %d is below the %d required for %d concurrent connections",
			hardLimit,
			required,
			args.Concurrent,
		)
	}
	if softLimit >= required {
		return nil
	}
	setRlimitCur(&limit.Cur, required)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return fmt.Errorf("raise file descriptor limit from %d to %d: %w", softLimit, required, err)
	}
	slog.Info("Raised file descriptor limit", "from", softLimit, "to", required, "hard_limit", hardLimit)
	return nil
}

// setRlimitCur assigns the requirement to an rlimit field whose integer type
// varies across Unix platforms (int64 on FreeBSD and DragonFly BSD, uint64
// elsewhere).
func setRlimitCur[T ~int64 | ~uint64](field *T, value uint64) {
	*field = T(value)
}
