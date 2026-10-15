// Command mtls-demo is a single binary with three subcommands: server,
// client and verifier. See README.md.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Cameloo1/labca/mtls-demo/internal/client"
	"github.com/Cameloo1/labca/mtls-demo/internal/server"
	"github.com/Cameloo1/labca/mtls-demo/internal/verifier"
)

const usage = "usage: mtls-demo server|client|verifier\n"

func logLevel(s string) slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(strings.TrimSpace(s))); err != nil || s == "" {
		return slog.LevelInfo
	}
	return l
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: logLevel(os.Getenv("LOG_LEVEL"))}))
	var fn func(context.Context, *slog.Logger) error
	switch args[1] {
	case "server":
		fn = server.Run
	case "client":
		fn = client.Run
	case "verifier":
		fn = verifier.Run
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err := fn(ctx, logger); err != nil {
		logger.Error("exiting", "subcommand", args[1], "error", err.Error())
		return 1
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
