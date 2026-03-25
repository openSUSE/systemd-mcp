package man

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetManPageParams struct {
	Name     string   `json:"name" jsonschema:"Name of the man page"`
	Section  int      `json:"section,omitempty" jsonschema:"Section of the man page (default 1)"`
	Offset   int      `json:"offset,omitempty" jsonschema:"Line offset for pagination"`
	Limit    int      `json:"limit,omitempty" jsonschema:"Maximum number of lines to return (default 500)"`
	Chapters []string `json:"chapters,omitempty" jsonschema:"List of chapters to retrieve (e.g. ['NAME', 'SYNOPSIS'])"`
}

// Executor interface for running external commands.
type Executor interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error)
}

// DefaultExecutor uses os/exec to run commands.
type DefaultExecutor struct{}

func (e *DefaultExecutor) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "COLUMNS=80", "MAN_POSIXLY_CORRECT=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

var globalExecutor Executor = &DefaultExecutor{}

func SetExecutor(e Executor) {
	globalExecutor = e
}

type ManPageResult struct {
	Content    string   `json:"content"`
	Chapters   []string `json:"chapters"`
	TotalLines int      `json:"total_lines"`
}

func CreateManPageSchema() *jsonschema.Schema {
	inputSchema, _ := jsonschema.For[GetManPageParams](nil)
	inputSchema.Properties["limit"].Default = json.RawMessage(`2000`)
	inputSchema.Properties["section"].Default = json.RawMessage(`"1"`)
	return inputSchema
}

func stripOverstrike(input string) string {
	re := regexp.MustCompile(`.\x08`)
	for {
		if !re.MatchString(input) {
			break
		}
		input = re.ReplaceAllString(input, "")
	}
	return input
}

func parseAndFilterManPage(cleanOutput string, params *GetManPageParams) ManPageResult {
	lines := strings.Split(cleanOutput, "\n")

	// Parse Chapters
	var chapterNames []string
	type chapter struct {
		name  string
		lines []string
	}
	var chapters []chapter
	var currentChapter *chapter

	for _, line := range lines {
		// Detect Header: Non-empty, starts with non-whitespace
		// We use a simplified heuristic that assumes headers are at column 0
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			header := strings.TrimSpace(line)
			// Man page headers are typically uppercase, but we take them as is for the list
			chapterNames = append(chapterNames, header)
			newChap := chapter{name: header, lines: []string{line}}
			chapters = append(chapters, newChap)
			currentChapter = &chapters[len(chapters)-1]
		} else {
			if currentChapter != nil {
				currentChapter.lines = append(currentChapter.lines, line)
			} else {
				// Handle preamble or content before first header if any
				// For now, we drop it or could attach to a "PREAMBLE" chapter
			}
		}
	}

	// Filter Chapters
	var filteredLines []string
	if len(params.Chapters) > 0 {
		reqChapters := make(map[string]bool)
		for _, c := range params.Chapters {
			reqChapters[strings.ToUpper(c)] = true
		}

		for _, chap := range chapters {
			// Case-insensitive comparison for user convenience
			if reqChapters[strings.ToUpper(chap.name)] {
				filteredLines = append(filteredLines, chap.lines...)
			}
		}
	} else {
		// Return all content if no chapters specified
		if len(chapters) > 0 {
			for _, chap := range chapters {
				filteredLines = append(filteredLines, chap.lines...)
			}
		} else {
			// If no chapters detected, return raw lines (fallback)
			filteredLines = lines
		}
	}

	totalLines := len(filteredLines)

	limit := params.Limit
	if limit <= 0 {
		limit = 2000
	}

	// Pagination
	end := params.Offset + limit
	if end > totalLines {
		end = totalLines
	}

	var resultLines []string
	if params.Offset < totalLines {
		resultLines = filteredLines[params.Offset:end]
	}

	content := strings.Join(resultLines, "\n")

	return ManPageResult{
		Content:    content,
		Chapters:   chapterNames,
		TotalLines: totalLines,
	}
}

var validManName = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

func GetManPage(ctx context.Context, req *mcp.CallToolRequest, params *GetManPageParams) (*mcp.CallToolResult, any, error) {
	if params.Name == "" {
		return nil, nil, fmt.Errorf("man page name is required")
	}

	if !validManName.MatchString(params.Name) {
		return nil, nil, fmt.Errorf("invalid man page name: %s (only a-z, A-Z, 0-9, and - are allowed)", params.Name)
	}

	section := params.Section
	if section == 0 {
		section = 1
	}

	// Try with specific section first: man 1 ls
	cmd := exec.Command("man", fmt.Sprint(section), params.Name)
	cmd.Env = append(cmd.Environ(), "COLUMNS=80", "MAN_POSIXLY_CORRECT=1")

	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Fallback: Try without section: man ls
		cmdFallback := exec.Command("man", params.Name)
		cmdFallback.Env = append(cmdFallback.Environ(), "COLUMNS=80", "MAN_POSIXLY_CORRECT=1")
		var outFallback bytes.Buffer
		cmdFallback.Stdout = &outFallback
		var stderrFallback bytes.Buffer
		cmdFallback.Stderr = &stderrFallback

		if errFallback := cmdFallback.Run(); errFallback != nil {
			// If fallback also fails, report the original error or a combined one
			errMsg := strings.TrimSpace(stderr.String())
			if errMsg == "" {
				errMsg = err.Error()
			}
			return nil, nil, fmt.Errorf("failed to get man page for %s(%d): %s", params.Name, section, errMsg)
		}
		// Fallback succeeded
		out = outFallback
	}

	rawOutput := out.String()
	cleanOutput := stripOverstrike(rawOutput)

	res := parseAndFilterManPage(cleanOutput, params)

	jsonBytes, err := json.Marshal(res)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal response: %w", err)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: string(jsonBytes),
			},
		},
	}, nil, nil
}
