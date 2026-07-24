package connect

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
)

var globalLogger atomic.Pointer[slog.Logger]

var fallbackLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func logger() *slog.Logger {
	if configured := globalLogger.Load(); configured != nil {
		return configured
	}
	return fallbackLogger
}

// debugEnabled reports whether debug logging is enabled, so dial hot paths can
// skip evaluating and boxing the arguments of disabled slog.Debug calls.
func debugEnabled() bool {
	return logger().Enabled(context.Background(), slog.LevelDebug)
}

// SetLogger allows the server runtime to inject a configured logger.
func SetLogger(l *slog.Logger) {
	globalLogger.Store(l)
}
