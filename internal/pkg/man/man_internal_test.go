package man

import (
	"reflect"
	"testing"
)

func TestStripOverstrike(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"abc", "abc"},
		{"a\b", ""},           // Backspace removes prev char
		{"ab\b", "a"},         // Backspace removes b
		{"_\bX", "X"},         // Underline X -> X
		{"X\bX", "X"},         // Bold X -> X
		{"H\bH\bHe\be", "He"}, // Bold He
	}

	for _, tt := range tests {
		got := stripOverstrike(tt.input)
		if got != tt.want {
			t.Errorf("stripOverstrike(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseAndFilterManPage(t *testing.T) {
	// Note: 9 lines total (including trailing empty line from Split)
	sampleContent := "NAME\n       ls - list directory contents\n\nSYNOPSIS\n       ls [OPTION]... [FILE]...\n\nDESCRIPTION\n       List information about the FILEs (the current directory by default).\n"

	tests := []struct {
		name         string
		content      string
		params       *GetManPageParams
		wantChapters []string
		wantTotal    int
		checkContent func(t *testing.T, content string)
	}{
		{
			name:         "Basic Parsing",
			content:      sampleContent,
			params:       &GetManPageParams{},
			wantChapters: []string{"NAME", "SYNOPSIS", "DESCRIPTION"},
			wantTotal:    9,
			checkContent: func(t *testing.T, content string) {
				if content != sampleContent {
					t.Errorf("Content mismatch. Got len %d, want len %d", len(content), len(sampleContent))
				}
			},
		},
		{
			name:    "Filter Chapter NAME",
			content: sampleContent,
			params: &GetManPageParams{
				Chapters: []string{"NAME"},
			},
			wantChapters: []string{"NAME", "SYNOPSIS", "DESCRIPTION"},
			wantTotal:    3, // NAME line + Content + Empty line
			checkContent: func(t *testing.T, content string) {
				expected := "NAME\n       ls - list directory contents\n"
				if content != expected {
					t.Errorf("Content mismatch.\nGot: %q\nWant: %q", content, expected)
				}
			},
		},
		{
			name:    "Pagination Limit 2",
			content: sampleContent,
			params: &GetManPageParams{
				Limit:  2,
				Offset: 0,
			},
			wantChapters: []string{"NAME", "SYNOPSIS", "DESCRIPTION"},
			wantTotal:    9, // Total lines in unfiltered result
			checkContent: func(t *testing.T, content string) {
				expected := "NAME\n       ls - list directory contents"
				if content != expected {
					t.Errorf("Content mismatch.\nGot: %q\nWant: %q", content, expected)
				}
			},
		},
		{
			name:    "Pagination Offset 3",
			content: sampleContent,
			params: &GetManPageParams{
				Limit:  500,
				Offset: 3,
			},
			wantChapters: []string{"NAME", "SYNOPSIS", "DESCRIPTION"},
			wantTotal:    9,
			checkContent: func(t *testing.T, content string) {
				// Offset 3 starts at SYNOPSIS (index 3)
				// Remaining lines: SYNOPSIS, Content, Empty, DESCRIPTION, Content, Empty
				expected := "SYNOPSIS\n       ls [OPTION]... [FILE]...\n\nDESCRIPTION\n       List information about the FILEs (the current directory by default).\n"
				if content != expected {
					t.Errorf("Content mismatch.\nGot: %q\nWant: %q", content, expected)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAndFilterManPage(tt.content, tt.params)

			if !reflect.DeepEqual(got.Chapters, tt.wantChapters) {
				t.Errorf("Chapters = %v, want %v", got.Chapters, tt.wantChapters)
			}

			if got.TotalLines != tt.wantTotal {
				t.Errorf("TotalLines = %d, want %d", got.TotalLines, tt.wantTotal)
			}

			if tt.checkContent != nil {
				tt.checkContent(t, got.Content)
			}
		})
	}
}

func TestGetManPageValidation(t *testing.T) {
	tests := []struct {
		name    string
		manName string
		wantErr bool
	}{
		{"ValidName", "ls", false},
		{"ValidNameWithHyphen", "systemd-analyze", false},
		{"InvalidCharSpace", "ls --help", true},
		{"InvalidCharSpecial", "ls; rm -rf /", true},
		{"EmptyName", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := &GetManPageParams{Name: tt.manName}
			_, _, err := GetManPage(nil, nil, params)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetManPage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
