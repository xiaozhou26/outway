package connect

import (
	"log/slog"
	"os"
)

var globalLogger *slog.Logger

func logger() *slog.Logger {
	if globalLogger != nil {
		return globalLogger
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// SetLogger allows the server runtime to inject a configured logger.
func SetLogger(l *slog.Logger) {
	globalLogger = l
}
