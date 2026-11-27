package file

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	auth "github.com/openSUSE/systemd-mcp/authkeeper"
	"log/slog"
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
	"github.com/openSUSE/systemd-mcp/internal/pkg/util"
)

type GetFileParams struct {
	Host        string `json:"host,omitempty" jsonschema:"Optional; defaults to the local machine (os.Hostname()). 'localhost' (and the empty value) reads this machine's filesystem. Any other value must be a host registered with the set_host tool first, in which case the file is read on that host over the SSH connection."`
	Path        string `json:"path" jsonschema:"Required. Absolute path to the file or directory to read (e.g. '/etc/systemd/system/ssh.service')."`
	ShowContent bool   `json:"show_content,omitempty" jsonschema:"Optional; defaults to false. When true, include the file's text content in the result (subject to offset/limit pagination). When reading a directory this field is ignored and only entries are returned."`
	Offset      int    `json:"offset,omitempty" jsonschema:"Optional; defaults to 0. Line offset for pagination (zero-based)."`
	Limit       int    `json:"limit,omitempty" jsonschema:"Optional; defaults to 1000. Maximum number of lines to return in one call."`
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
	Host       string         `json:"host"`
	Metadata   *FileMetadata  `json:"metadata"`
	Entries    []FileMetadata `json:"entries,omitempty"`
	Content    string         `json:"content,omitempty"`
	TotalLines int            `json:"total_lines,omitempty"`
	Offset     int            `json:"offset,omitempty"`
	Limit      int            `json:"limit,omitempty"`
}

func CreateFileSchema() *jsonschema.Schema {
	inputSchema, _ := jsonschema.For[GetFileParams](nil)
	inputSchema.Properties["host"].Default = json.RawMessage("\"localhost\"")
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
		cmd := exec.CommandContext(ctx, "getfacl", "-p", "--", path)
		out, err := cmd.Output()
		if err == nil {
			metadata.ACLs = string(out)
		}
	}

	return metadata
}

type remoteRunner interface {
	RunRemote(ctx context.Context, req *mcp.CallToolRequest, hostName, command string) (string, string, int, error)
}

// remoteGetFile reads a remote file or directory over the SSH exec channel.
// It issues a small number of well-known commands against the remote host
// (stat / find / cat) so that neither the local journal group, gatekeeper nor
// even local filesystem access is required to serve the result.
func remoteGetFile(ctx context.Context, req *mcp.CallToolRequest, params *GetFileParams, remote remoteRunner) (*mcp.CallToolResult, any, error) {
	path := params.Path
	// stat -c format: mode|size|uid|gid|mtime|type ; first line wins (we use
	// -- on the path to dodge leading '-' and we capture stderr so that a
	// non-zero exit surfaces a clear message even if stdout is empty)
	statOut, _, code, err := remote.RunRemote(ctx, req, params.Host,
		fmt.Sprintf("stat -c '%%A|%%s|%%u|%%g|%%Y|%%F' -- %q 2>&1", path))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat remote path %q: %w", path, err)
	}
	if code != 0 {
		return nil, nil, fmt.Errorf("remote stat of %q failed (status %d): %s", path, code, strings.TrimSpace(statOut))
	}

	metadata := &FileMetadata{}
	for _, line := range strings.Split(statOut, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 6)
		if len(parts) < 6 {
			continue
		}
		metadata.IsDir = strings.Contains(parts[5], "directory")
		metadata.Mode = parts[0]
		metadata.Size, _ = strconv.ParseInt(parts[1], 10, 64)
		uid, _ := strconv.ParseInt(parts[2], 10, 32)
		gid, _ := strconv.ParseInt(parts[3], 10, 32)
		metadata.Owner = strconv.Itoa(int(uid))
		metadata.Group = strconv.Itoa(int(gid))
		modSecs, _ := strconv.ParseInt(parts[4], 10, 64)
		metadata.ModTime = time.Unix(modSecs, 0).UTC().Format(time.RFC3339)
		break // first line wins
	}
	if metadata.Mode == "" {
		return nil, nil, fmt.Errorf("remote stat of %q returned no data", path)
	}

	result := &GetFileResult{
		Host:     util.HostName(params.Host),
		Metadata: metadata,
	}

	if metadata.IsDir {
		// list immediate children; find's %n is 0 for files, 1 for other, 2 for dirs
		// we use %p (full path) and %y (file type letter) so we can derive
		// isDir and just report the basename
		// find -printf fields: %y (file type: d=dir, f=file,...) | %s (size) |
		// %u (uid) | %g (gid) | %Y (mtime epoch) | %m (mode octal) | %P (name
		// relative to the starting point, i.e. the entry name itself)
		lstOut, _, lcode, lerr := remote.RunRemote(ctx, req, params.Host,
			fmt.Sprintf("find %q -mindepth 1 -maxdepth 1 -printf '%%y|%%s|%%u|%%g|%%Y|%%m|%%P\\n' 2>&1", path))
		if lerr != nil {
			return nil, nil, fmt.Errorf("failed to read remote directory %q: %w", path, lerr)
		}
		if lcode != 0 {
			return nil, nil, fmt.Errorf("remote find of %q failed: %s", path, strings.TrimSpace(lstOut))
		}
		for _, line := range strings.Split(strings.TrimSpace(lstOut), "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 7)
			if len(parts) < 7 {
				continue
			}
			entry := &FileMetadata{}
			entry.IsDir = parts[0] == "d"
			entry.Size, _ = strconv.ParseInt(parts[1], 10, 64)
			uid, _ := strconv.ParseInt(parts[2], 10, 32)
			gid, _ := strconv.ParseInt(parts[3], 10, 32)
			modSecs, _ := strconv.ParseInt(parts[4], 10, 64)
			entry.Owner = strconv.Itoa(int(uid))
			entry.Group = strconv.Itoa(int(gid))
			entry.ModTime = time.Unix(modSecs, 0).UTC().Format(time.RFC3339)
			entry.Mode = parts[5]
			entry.Name = parts[6]
			result.Entries = append(result.Entries, *entry)
		}
	} else if params.ShowContent {
		// pull content and paginate locally (matches the local implementation)
		content, _, ccode, cerr := remote.RunRemote(ctx, req, params.Host,
			fmt.Sprintf("cat -- %q 2>&1", path))
		if cerr != nil {
			return nil, nil, fmt.Errorf("failed to read remote file %q: %w", path, cerr)
		}
		if ccode != 0 {
			return nil, nil, fmt.Errorf("remote cat of %q failed: %s", path, strings.TrimSpace(content))
		}
		limit := params.Limit
		if limit <= 0 {
			limit = 1000
		}
		lines := strings.Split(content, "\n")
		// trailing newline: keep the last empty entry if file ended with \n
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		total := len(lines)
		offset := params.Offset
		if offset < 0 {
			offset = 0
		}
		end := offset + limit
		if end > total {
			end = total
		}
		if offset <= total {
			if end > offset {
				result.Content = strings.Join(lines[offset:end], "\n")
			}
		}
		result.TotalLines = total
		result.Offset = offset
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

// reads a file with the privileges of the systemd service
//
// When params.Host is a registered remote host, the file is read over the SSH
// connection (via the runner.RunRemote) which reuses the same trust /
// auth setup as the local path. Otherwise the local filesystem is read.
func GetFile(ctx context.Context, req *mcp.CallToolRequest, params *GetFileParams, authKeeper auth.AuthKeeper, remote remoteRunner) (*mcp.CallToolResult, any, error) {
	if params.Host != "" && !util.IsLocal(params.Host) {
		if remote == nil {
			return nil, nil, fmt.Errorf("no remote SSH connection available for host %q; register it with the set_host tool or run systemd-mcp on that host", params.Host)
		}
		return remoteGetFile(ctx, req, params, remote)
	}
	if allowed, err := authKeeper.IsReadAuthorized(ctx); err != nil {
		return nil, nil, err
	} else if !allowed {
		return nil, nil, fmt.Errorf("calling method was canceled by user")
	}
	// 'localhost' is a synonym for the local machine, so resolve the effective host
	slog.Debug("GetFile called", "resolved_host", util.HostName(params.Host), "path", params.Path)
	info, err := os.Stat(params.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat file: %w", err)
	}

	metadata := getFileMetadata(ctx, params.Path, info, true)

	result := &GetFileResult{
		Host:     util.LocalHostName(),
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
