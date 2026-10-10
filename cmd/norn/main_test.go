package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestMain gives the package's run one private directory for the norn binary
// the end-to-end tests build, and removes it when the run ends. nornBinary
// used to build into the system temp directory under the process id and
// nothing removed it: 250 of them, 3.2 GB, had collected by 2026-10-09.
func TestMain(m *testing.M) {
	os.Exit(withBinaryDir(func(dir string) int {
		nornBinDir = dir
		return m.Run()
	}))
}

// The directory's lifetime cannot be tested from inside the run it belongs
// to, so the helper TestMain uses is tested instead: it creates a directory,
// hands it over, and removes it and everything in it afterwards -- after a
// failing run as well as a passing one, whose exit code it returns unchanged.
func TestTheBinaryDirectoryIsRemovedAfterTheRun(t *testing.T) {
	for _, code := range []int{0, 1} {
		t.Run(fmt.Sprintf("exit-%d", code), func(t *testing.T) {
			var dir string
			got := withBinaryDir(func(path string) int {
				dir = path
				info, err := os.Stat(dir)
				if err != nil {
					t.Fatalf("binary directory must exist during the run: %v", err)
				}
				if !info.IsDir() {
					t.Fatal("binary path must be a directory")
				}
				if err := os.WriteFile(filepath.Join(dir, "norn"), []byte("binary"), 0o755); err != nil {
					t.Fatal(err)
				}
				return code
			})
			if dir == "" {
				t.Fatal("the run must be called")
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			if got != code {
				t.Errorf("exit code = %d, want %d", got, code)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Errorf("binary directory must be removed after exit %d: %v", code, err)
			}
		})
	}
}

// withBinaryDir runs run with a fresh directory and removes the directory
// however run returns. A test that panics ends the process before this
// returns, so that run leaves its one directory behind -- one per crash, not
// one per run.
func withBinaryDir(run func(string) int) int {
	dir, err := os.MkdirTemp("", "norn-cli-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "creating norn binary directory: %v\n", err)
		return 1
	}
	defer os.RemoveAll(dir)
	return run(dir)
}
