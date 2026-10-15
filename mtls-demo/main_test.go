package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestUsageExitCode(t *testing.T) {
	for _, args := range [][]string{{"mtls-demo"}, {"mtls-demo", "bogus"}} {
		var out, errb bytes.Buffer
		if code := run(context.Background(), args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if !strings.Contains(errb.String(), "usage:") || out.Len() != 0 {
			t.Errorf("%v: usage should go to stderr only", args)
		}
	}
}

func TestSubcommandErrorExitsOne(t *testing.T) {
	t.Setenv("ALLOWED_CLIENT_IDS", "")
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"mtls-demo", "server"}, &out, &errb); code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if !strings.Contains(out.String(), "ALLOWED_CLIENT_IDS") {
		t.Errorf("error should be logged as JSON on stdout: %q", out.String())
	}
}

func TestLogLevel(t *testing.T) {
	if logLevel("") != slog.LevelInfo || logLevel("nonsense") != slog.LevelInfo {
		t.Error("default must be info")
	}
	if logLevel("debug") != slog.LevelDebug || logLevel("ERROR") != slog.LevelError {
		t.Error("level parsing")
	}
}
