package cmd

import (
	"os"
	"testing"

	"github.com/gookit/color"
)

func TestGetScoreColor(t *testing.T) {
	tests := []struct {
		name     string
		score    int
		expected color.Color
	}{
		{"score 100 should be green", 100, color.Green},
		{"score 90 should be green", 90, color.Green},
		{"score 89 should be yellow", 89, color.Yellow},
		{"score 70 should be yellow", 70, color.Yellow},
		{"score 50 should be yellow", 50, color.Magenta},
		{"score 49 should be red", 49, color.Red},
		{"score 0 should be red", 0, color.Red},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getScoreColor(tt.score)
			if result != tt.expected {
				t.Errorf("getScoreColor(%d) = %v, want %v", tt.score, result, tt.expected)
			}
		})
	}
}

func TestGetGradeColor(t *testing.T) {
	tests := []struct {
		name     string
		grade    string
		expected color.Color
	}{
		{"A+ should be green", "A+", color.Green},
		{"A should be green", "A", color.Green},
		{"A- should be green", "A-", color.Green},
		{"B+ should be yellow", "B+", color.Yellow},
		{"B should be yellow", "B", color.Yellow},
		{"B- should be yellow", "B-", color.Yellow},
		{"C should be yellow", "C", color.Magenta},
		{"D should be yellow", "D", color.Red},
		{"F should be red", "F", color.Red},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getGradeColor(tt.grade)
			if result != tt.expected {
				t.Errorf("getGradeColor(%s) = %v, want %v", tt.grade, result, tt.expected)
			}
		})
	}
}

func TestParseCustomHeaders(t *testing.T) {
	tests := []struct {
		name     string
		headers  []string
		expected map[string]string
	}{
		{
			name:     "empty headers",
			headers:  []string{},
			expected: map[string]string{},
		},
		{
			name:    "single header",
			headers: []string{"X-Custom: value"},
			expected: map[string]string{
				"X-Custom": "value",
			},
		},
		{
			name:    "multiple headers",
			headers: []string{"X-Custom: value", "Authorization: Bearer token"},
			expected: map[string]string{
				"X-Custom":      "value",
				"Authorization": "Bearer token",
			},
		},
		{
			name:    "header with colon in value",
			headers: []string{"X-Custom: key:value:test"},
			expected: map[string]string{
				"X-Custom": "key:value:test",
			},
		},
		{
			name:    "header with spaces",
			headers: []string{"  X-Custom  :  value  "},
			expected: map[string]string{
				"X-Custom": "value",
			},
		},
		{
			name:     "invalid header without colon",
			headers:  []string{"Invalid-Header"},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCustomHeaders(tt.headers)
			if len(result) != len(tt.expected) {
				t.Errorf(
					"parseCustomHeaders() returned %d headers, want %d",
					len(result),
					len(tt.expected),
				)
			}
			for key, expectedValue := range tt.expected {
				if result[key] != expectedValue {
					t.Errorf(
						"parseCustomHeaders()[%s] = %s, want %s",
						key,
						result[key],
						expectedValue,
					)
				}
			}
		})
	}
}

func TestLoadTargetsFromFile(t *testing.T) {
	// Create a temporary test file
	tmpfile := t.TempDir() + "/hosts.txt"
	content := `# Comment line
example.com
https://google.com

# Another comment
github.com
`
	if err := os.WriteFile(tmpfile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	targets, err := loadTargetsFromFile(tmpfile)
	if err != nil {
		t.Fatalf("loadTargetsFromFile() error = %v", err)
	}

	expected := []string{"example.com", "https://google.com", "github.com"}
	if len(targets) != len(expected) {
		t.Errorf("loadTargetsFromFile() returned %d targets, want %d", len(targets), len(expected))
	}

	for i, target := range targets {
		if target != expected[i] {
			t.Errorf("loadTargetsFromFile()[%d] = %s, want %s", i, target, expected[i])
		}
	}
}

func TestLoadTargetsFromFileNotFound(t *testing.T) {
	_, err := loadTargetsFromFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("loadTargetsFromFile() should return error for nonexistent file")
	}
}

func TestLoadTargetsFromFileEmpty(t *testing.T) {
	tmpfile := t.TempDir() + "/empty.txt"
	if err := os.WriteFile(tmpfile, []byte(""), 0600); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	targets, err := loadTargetsFromFile(tmpfile)
	if err != nil {
		t.Fatalf("loadTargetsFromFile() error = %v", err)
	}

	if len(targets) != 0 {
		t.Errorf("loadTargetsFromFile() returned %d targets, want 0", len(targets))
	}
}
