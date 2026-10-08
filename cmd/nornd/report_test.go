package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/onembyte/norn/internal/agent"
	"github.com/onembyte/norn/internal/reconcile"
)

// Discover the kinds from their declarations rather than a second hand-kept
// list, so a new event cannot inherit Info just because this test missed it.
// Both packages name their event kinds with uppercase string constants; modes,
// fight policies and directory names use lowercase strings instead.
func TestEveryDeclaredEventKindHasAnExplicitLogLevel(t *testing.T) {
	kindName := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	found := 0
	for _, pkg := range []string{"agent", "reconcile"} {
		files, err := filepath.Glob(filepath.Join("..", "..", "internal", pkg, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				constants, ok := decl.(*ast.GenDecl)
				if !ok || constants.Tok != token.CONST {
					continue
				}
				for _, spec := range constants.Specs {
					for _, value := range spec.(*ast.ValueSpec).Values {
						literal, ok := value.(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							continue
						}
						kind, err := strconv.Unquote(literal.Value)
						if err != nil {
							t.Fatal(err)
						}
						if !kindName.MatchString(kind) {
							continue
						}
						found++
						if _, ok := eventLevels[kind]; !ok {
							t.Errorf("%s: event kind %s has no explicit log level", path, kind)
						}
					}
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no event kinds were enumerated")
	}
	if found != len(eventLevels) {
		t.Errorf("enumerated %d event kinds, level table has %d", found, len(eventLevels))
	}
}

func TestEveryEventIsReportedAtItsDeliberateLogLevel(t *testing.T) {
	cases := map[string]slog.Level{
		agent.Fork:                  slog.LevelError,
		agent.Frozen:                slog.LevelError,
		agent.HardStale:             slog.LevelError,
		agent.Quarantined:           slog.LevelError,
		agent.QuarantineFailed:      slog.LevelError,
		agent.Degraded:              slog.LevelWarn,
		agent.MirrorUnusable:        slog.LevelWarn,
		agent.MirrorFailed:          slog.LevelWarn,
		agent.ClockSkew:             slog.LevelWarn,
		reconcile.UnprovenPeer:      slog.LevelWarn,
		reconcile.EvictedPeer:       slog.LevelWarn,
		agent.VerifyFailed:          slog.LevelWarn,
		agent.EnforcingOnStaleState: slog.LevelWarn,
		agent.InterfaceUnavailable:  slog.LevelWarn,
		agent.InterfaceUnconfigured: slog.LevelWarn,
		agent.ControlPlaneFight:     slog.LevelWarn,
		agent.PeerRefused:           slog.LevelWarn,
		agent.AdoptedFromPeer:       slog.LevelWarn,
		agent.NoStateYet:            slog.LevelWarn,
		agent.ProviderClaim:         slog.LevelWarn,
		reconcile.MissingPeer:       slog.LevelInfo,
		"UNKNOWN_EVENT":             slog.LevelError,
	}
	for kind, want := range cases {
		t.Run(kind, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			report(logger, agent.Event{Kind: kind, Message: "event message"})
			var record struct {
				Level string `json:"level"`
				Kind  string `json:"kind"`
				Msg   string `json:"msg"`
			}
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record.Level != want.String() {
				t.Errorf("%s logged at %s, want %s", kind, record.Level, want)
			}
			if record.Kind != kind || record.Msg != "event message" {
				t.Errorf("event fields were lost: %+v", record)
			}
		})
	}
}
