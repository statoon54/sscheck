package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestGetInfo(t *testing.T) {
	info := GetInfo()

	if info.Version == "" {
		t.Error("Version should not be empty")
	}

	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion = %s, want %s", info.GoVersion, runtime.Version())
	}

	if info.OS != runtime.GOOS {
		t.Errorf("OS = %s, want %s", info.OS, runtime.GOOS)
	}

	if info.Arch != runtime.GOARCH {
		t.Errorf("Arch = %s, want %s", info.Arch, runtime.GOARCH)
	}
}

func TestInfoString(t *testing.T) {
	info := GetInfo()
	str := info.String()

	if !strings.Contains(str, "sscheck") {
		t.Error("String() should contain 'sscheck'")
	}

	if !strings.Contains(str, info.Version) {
		t.Error("String() should contain version")
	}

	if !strings.Contains(str, info.GoVersion) {
		t.Error("String() should contain Go version")
	}
}

func TestShort(t *testing.T) {
	short := Short()
	if short != Version {
		t.Errorf("Short() = %s, want %s", short, Version)
	}
}

func TestFull(t *testing.T) {
	full := Full()
	info := GetInfo()

	if full != info.String() {
		t.Errorf("Full() = %s, want %s", full, info.String())
	}
}

func TestDefaultValues(t *testing.T) {
	if Version == "" {
		t.Error("Version should have a default value")
	}

	if Commit == "" {
		t.Error("Commit should have a default value")
	}

	if Date == "" {
		t.Error("Date should have a default value")
	}
}
