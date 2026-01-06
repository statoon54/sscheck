package version

import (
	"fmt"
	"runtime"
)

// Version information set at build time via ldflags
var (
	// Version is the semantic version (e.g., "1.0.0")
	Version = "dev"
	// Commit is the git commit SHA
	Commit = "unknown"
	// Date is the build date
	Date = "unknown"
)

// Info contains the full version information
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// GetInfo returns the full version information
func GetInfo() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// String returns a human-readable version string
func (i Info) String() string {
	return fmt.Sprintf("sscheck %s (commit: %s, built: %s, %s, %s/%s)",
		i.Version, i.Commit, i.Date, i.GoVersion, i.OS, i.Arch)
}

// Short returns a short version string
func Short() string {
	return Version
}

// Full returns the full version string
func Full() string {
	return GetInfo().String()
}
