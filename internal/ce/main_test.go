package ce

import (
	"log/slog"
	"os"
	"testing"
)

var testLogLevel = func() slog.Level {
	if os.Getenv("CEDAR_DEBUG") != "" {
		return slog.LevelDebug
	}
	return slog.LevelWarn
}()

func TestMain(m *testing.M) {
	// cedar logs every handshake step at INFO through the default logger.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: testLogLevel})))
	os.Exit(m.Run())
}
