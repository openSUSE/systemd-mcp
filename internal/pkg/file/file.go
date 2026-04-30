package file

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	auth "github.com/openSUSE/systemd-mcp/authkeeper"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetFileParams struct {
	Path        string `json:"path" jsonschema:"Absolute path to the file"`
	ShowContent bool   `json:"show_content,omitempty" jsonschema:"Whether to show file content. Defaults to false."`
	Offset      int    `json:"offset,omitempty" jsonschema:"Line offset for pagination. Defaults to 0."`
	Limit       int    `json:"limit,omitempty" jsonschema:"Line limit for pagination. Defaults to 1000."`
}

type FileMetadata struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	Owner   string `json:"owner"`
	Group   string `json:"group"`
	ModTime string `json:"mod_time"`
	ACLs    string `json:"acls,omitempty"`
	IsDir   bool   `json:"is_dir"`
}

type GetFileResult struct {
	Metadata   *FileMetadata  `json:"metadata"`
	Entries    []FileMetadata `json:"entries,omitempty"`
	Content    string         `json:"content,omitempty"`
	TotalLines int            `json:"total_lines,omitempty"`
	Offset     int            `json:"offset,omitempty"`
	Limit      int            `json:"limit,omitempty"`
}

func CreateFileSchema() *jsonschema.Schema {
	inputSchema, _ := jsonschema.For[GetFileParams](nil)
	inputSchema.Properties["limit"].Default = json.RawMessage(`1000`)
	inputSchema.Properties["offset"].Default = json.RawMessage(`0`)
	inputSchema.Properties["show_content"].Default = json.RawMessage(`false`)
	return inputSchema
}

func getFileMetadata(ctx context.Context, path string, info os.FileInfo, fetchACLs bool) *FileMetadata {
	metadata := &FileMetadata{
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().Format(time.RFC3339),
		IsDir:   info.IsDir(),
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := strconv.FormatUint(uint64(stat.Uid), 10)
		gid := strconv.FormatUint(uint64(stat.Gid), 10)

		u, err := user.LookupId(uid)
		if err == nil {
			metadata.Owner = u.Username
		} else {
			metadata.Owner = uid
		}

		g, err := user.LookupGroupId(gid)
		if err == nil {
			metadata.Group = g.Name
		} else {
			metadata.Group = gid
		}
	}

	if fetchACLs {
		// Try to get ACLs
		cmd := exec.CommandContext(ctx, "getfacl", "-p", path)
		out, err := cmd.Output()
		if err == nil {
			metadata.ACLs = string(out)
		}
	}

	return metadata
}

// reads a file with the privileges of the systemd service
func GetFile(ctx context.Context, req *mcp.CallToolRequest, params *GetFileParams, authKeeper auth.AuthKeeper) (*mcp.CallToolResult, any, error) {
	if allowed, err := authKeeper.IsReadAuthorized(ctx); err != nil {
		return nil, nil, err
	} else if !allowed {
		return nil, nil, fmt.Errorf("calling method was canceled by user")
	}
	info, err := os.Stat(params.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat file: %w", err)
	}

	metadata := getFileMetadata(ctx, params.Path, info, true)

	result := &GetFileResult{
		Metadata: metadata,
	}

	if info.IsDir() {
		entries, err := os.ReadDir(params.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read directory: %w", err)
		}

		var fileEntries []FileMetadata
		for _, entry := range entries {
			entryInfo, err := entry.Info()
			if err != nil {
				continue
			}
			meta := getFileMetadata(ctx, filepath.Join(params.Path, entry.Name()), entryInfo, false)
			fileEntries = append(fileEntries, *meta)
		}
		result.Entries = fileEntries
	} else if params.ShowContent {
		f, err := os.Open(params.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer f.Close()

		limit := params.Limit
		if limit <= 0 {
			limit = 1000
		}

		// Count lines or read with limit
		// Since we need to paginate, we might need to scan through lines.
		// For huge files, this is inefficient, but simple for now.
		// An optimization would be to seek if lines are fixed width, but they aren't.

		var lines []string
		scanner := bufio.NewScanner(f)
		lineCount := 0
		linesRead := 0

		// If offset is huge, this is slow.
		// But usually we just read config files.
		for scanner.Scan() {
			if lineCount >= params.Offset && linesRead < limit {
				lines = append(lines, scanner.Text())
				linesRead++
			}
			lineCount++
		}

		if err := scanner.Err(); err != nil {
			// Handle token too long or other errors?
			// For now just return what we have or error.
			if err != bufio.ErrTooLong {
				return nil, nil, fmt.Errorf("error reading file: %w", err)
			}
		}

		result.Content = strings.Join(lines, "\n")
		result.TotalLines = lineCount
		result.Offset = params.Offset
		result.Limit = limit
	}

	jsonBytes, err := json.Marshal(result)
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
