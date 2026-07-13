package connect

import (
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

// SetLogger allows the server runtime to inject a configured logger.
func SetLogger(l *slog.Logger) {
	globalLogger.Store(l)
}
