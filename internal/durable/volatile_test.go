package durable

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestAnOrdinaryDirectoryCanBeAsked(t *testing.T) {
	volatile, err := Volatile(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "linux" && volatile {
		t.Error("a directory was called volatile on a system this check does not cover")
	}
}

func TestATmpfsIsVolatile(t *testing.T) {
	raw, err := os.ReadFile("/proc/mounts")
	if err != nil || !strings.Contains(string(raw), " /dev/shm tmpfs ") {
		t.Skip("no tmpfs at /dev/shm on this machine; the Linux CI runner has one")
	}
	volatile, err := Volatile("/dev/shm")
	if err != nil || !volatile {
		t.Errorf("/dev/shm is a tmpfs and was not called volatile (%v)", err)
	}
}

func TestAMissingDirectoryIsAnError(t *testing.T) {
	if _, err := Volatile("/nonexistent/norn/state"); err == nil && runtime.GOOS == "linux" {
		t.Error("asked about a directory that does not exist, and got an answer")
	}
}
