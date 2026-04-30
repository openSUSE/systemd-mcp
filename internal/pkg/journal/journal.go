package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	auth "github.com/openSUSE/systemd-mcp/authkeeper"
	"github.com/openSUSE/systemd-mcp/internal/pkg/man"
	"github.com/openSUSE/systemd-mcp/internal/pkg/sdjournalw"
)

type HostLog struct {
	journal *sdjournal.Journal
	Auth    auth.AuthKeeper
}

// Close the log and underlying journal
func (log *HostLog) Close() error {
	return log.journal.Close()
}

type ListLogParams struct {
	Count     int       `json:"count,omitempty" jsonschema:"Number of log lines to output"`
	Offset    int       `json:"offset,omitempty" jsonschema:"Number of newest log entries to skip for pagination"`
	From      time.Time `json:"from,omitempty" jsonschema:"Start time for filtering logs"`
	To        time.Time `json:"to,omitempty" jsonschema:"End time for filtering logs "`
	Pattern   string    `json:"pattern,omitempty" jsonschema:"Regular expression pattern to filter log messages or units."`
	Unit      []string  `json:"unit,omitempty" jsonschema:"Names of the service/unit from which to get the logs. Without an unit name the entries of all units are returned. The first field treated a regular expression if not set otherwise"`
	ExactUnit bool      `json:"exact_unit,omitempty" jsonschema:"Treat the first name unit as exact idendtifier and not as regular expression"`
	AllBoots  bool      `json:"allboots,omitempty" jsonschema:"Get the log entries from all boots, not just the active one"`
}

type LogOutput struct {
	Time       time.Time `json:"time"`
	Identifier string    `json:"identifier,omitempty"`
	UnitName   string    `json:"unit_name,omitempty"`
	ExeName    string    `json:"exe_name,omitempty"`
	Host       string    `json:"host,omitempty"`
	Msg        string    `json:"message"`
	Boot       string    `json:"bootid,omitempty"`
}

type ManPage struct {
	Name        string `json:"name"`
	Section     string `json:"section"`
	Description string `json:"description"`
}

type ListLogResult struct {
	Host          string      `json:"host"`
	NrMessages    int         `json:"nr_messages"`
	Hint          string      `json:"hint,omitempty"`
	Documentation []ManPage   `json:"documentation,omitempty"`
	Messages      []LogOutput `json:"messages"`
	Identifier    string      `json:"identifier,omitempty"`
	UnitName      string      `json:"unit_name,omitempty"`
}

var validManSection = regexp.MustCompile(man.ValidManSectionPattern)

func CreateListLogsSchema() *jsonschema.Schema {
	inputSchema, _ := jsonschema.For[ListLogParams](nil)
	inputSchema.Properties["count"].Default = json.RawMessage(`100`)
	inputSchema.Properties["offset"].Default = json.RawMessage(`0`)
	// inputSchema.Properties["pattern"].Default = json.RawMessage(`""`)

	return inputSchema
}

func (sj *HostLog) seekAndSkip(count uint64, offset uint64) (uint64, error) {
	if err := sj.journal.SeekTail(); err != nil {
		return 0, fmt.Errorf("failed to seek to end: %w", err)
	}
	// Skip offset entries first
	var skipOffset uint64
	if offset > 0 {
		var err error
		if skipOffset, err = sj.journal.PreviousSkip(offset); err != nil {
			return 0, fmt.Errorf("failed to skip offset entries: %w", err)
		}
	}
	if skip, err := sj.journal.PreviousSkip(count); err != nil {
		return 0, fmt.Errorf("failed to move back entries: %w", err)
	} else {
		return skipOffset + skip, nil
	}
}

func (sj *HostLog) seekByTimeRange(params *ListLogParams) error {
	var fromTime, toTime time.Time
	// var err error

	if !params.From.IsZero() {
		fromTime = params.From
	}

	if !params.To.IsZero() {
		toTime = params.To
	}

	// Validate time range
	if !params.From.IsZero() && !params.To.IsZero() {
		if fromTime.After(toTime) {
			return fmt.Errorf("from time cannot be after to time")
		}
	}

	if !params.To.IsZero() {
		toMicros := uint64(toTime.UnixNano() / 1000)
		if err := sj.journal.SeekRealtimeUsec(toMicros); err != nil {
			return fmt.Errorf("failed to seek to time range: %w", err)
		}
	} else {
		if err := sj.journal.SeekTail(); err != nil {
			return fmt.Errorf("failed to seek to end: %w", err)
		}
	}

	// If we have pagination offset, apply it after time seeking
	if params.Offset > 0 {
		if _, err := sj.journal.PreviousSkip(uint64(params.Offset)); err != nil {
			return fmt.Errorf("failed to skip offset entries: %w", err)
		}
	}

	return nil
}

func (sj *HostLog) isJournalGroupMember() bool {
	info, err := os.Stat("/var/log/journal")
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	journalGid := stat.Gid

	if uint32(os.Getgid()) == journalGid {
		return true
	}

	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, gid := range groups {
		if uint32(gid) == journalGid {
			return true
		}
	}
	return false
}

// this is a very unusual function, as we have two cases here:
//  1. we run as root and have to asek via ouath2 that we are allowed to
//     acess the journal
//  2. we run as user and have to get the file pointer from the gatekeeper
//     which triggers a polkit call. If the gatekeeper service isn't
//     running we also have to start it
//
// In both cases we only want to annoy the user with a oauth2 or pplkit
// call only if access to the log is requested and not at every startup.
// This isn't an ideal solution, but I couldn't think of a better one
func (sj *HostLog) self_init(ctx context.Context) (allowed bool, err error) {
	if sj.journal != nil {
		return sj.Auth.IsReadAuthorized(ctx)
	} else if os.Geteuid() == 0 || sj.isJournalGroupMember() {
		// running as root or in journal group, ask via oauth2 is read is authorized, if yes
		// and journal isn't opened, open it
		j, err := sdjournal.NewJournal()
		if err != nil {
			return false, fmt.Errorf("failed to open journal: %w", err)
		}
		sj.journal = j
	} else {
		addr, err := net.ResolveUnixAddr("unix", "/run/gatekeeper/gatekeeper.socket")
		if err != nil {
			return false, fmt.Errorf("failed to resolve gatekeeper socket: %w", err)
		}
		conn, err := net.DialUnix("unix", nil, addr)
		if err != nil {
			return false, fmt.Errorf("failed to connect to gatekeeper: %w", err)
		}
		defer conn.Close()

		buf := make([]byte, 32)
		oob := make([]byte, syscall.CmsgSpace(256*4)) // space for 256 fds
		n, oobn, flags, _, err := conn.ReadMsgUnix(buf, oob)
		if err != nil {
			return false, fmt.Errorf("failed to read from gatekeeper: %w", err)
		}

		if flags&syscall.MSG_CTRUNC != 0 {
			return false, fmt.Errorf("gatekeeper sent too many file descriptors (control message truncated)")
		}

		if string(buf[:n]) != "OK\n" {
			return false, fmt.Errorf("gatekeeper error: %s", string(buf[:n]))
		}

		cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(cmsgs) == 0 {
			return false, fmt.Errorf("no fds received from gatekeeper")
		}

		fds, err := syscall.ParseUnixRights(&cmsgs[0])
		if err != nil || len(fds) == 0 {
			return false, fmt.Errorf("no fds received from gatekeeper")
		}

		uintFds := make([]uintptr, len(fds))
		for i, fd := range fds {
			uintFds[i] = uintptr(fd)
		}

		j, err := sdjournalwarp.NewJournalFromHandle(uintFds)
		if err != nil {
			return false, fmt.Errorf("failed to open journal from fd: %w", err)
		}
		sj.journal = &j.Journal
	}
	// if journal can be read don't do any more auth calling
	if !sj.isJournalGroupMember() {
		allowed, err = sj.Auth.IsReadAuthorized(ctx)
		if err != nil || !allowed {
			return allowed, err
		}
	}
	return true, nil
}

// get the lat log entries for a given unit, else just the last messages
func (sj *HostLog) ListLog(ctx context.Context, req *mcp.CallToolRequest, params *ListLogParams) (*mcp.CallToolResult, any, error) {
	// always init the host log via self initialization, not via init or
	allowed, err := sj.self_init(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !allowed {
		return nil, nil, fmt.Errorf("calling method was canceled by user")
	}
	sj.journal.FlushMatches()
	if len(params.Unit) > 0 {
		firstUnit := params.Unit[0]
		var re *regexp.Regexp
		var err error
		if !params.ExactUnit {
			re, err = regexp.Compile(firstUnit)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid regular expression in unit: %w", err)
			}
		}

		if re != nil {
			fields := []string{"SYSLOG_IDENTIFIER", "_SYSTEMD_USER_UNIT", "_SYSTEMD_UNIT"}
			added := false
			for _, field := range fields {
				values, err := sj.journal.GetUniqueValues(field)
				if err != nil {
					continue
				}
				for _, v := range values {
					if re.MatchString(v) {
						if added {
							if err := sj.journal.AddDisjunction(); err != nil {
								return nil, nil, err
							}
						}
						if err := sj.journal.AddMatch(field + "=" + v); err != nil {
							return nil, nil, err
						}
						added = true
					}
				}
			}
			if added {
				if err := sj.journal.AddConjunction(); err != nil {
					return nil, nil, err
				}
			} else {
				if err := sj.journal.AddMatch("_SYSTEMD_UNIT=__NO_MATCH__"); err != nil {
					return nil, nil, err
				}
				if err := sj.journal.AddConjunction(); err != nil {
					return nil, nil, err
				}
			}
		} else {
			if err := sj.journal.AddMatch("SYSLOG_IDENTIFIER=" + firstUnit); err != nil {
				return nil, nil, fmt.Errorf("failed to add unit filter: %w", err)
			}
			if err := sj.journal.AddDisjunction(); err != nil {
				return nil, nil, err
			}
			if err := sj.journal.AddMatch("_SYSTEMD_USER_UNIT=" + firstUnit); err != nil {
				return nil, nil, fmt.Errorf("failed to add unit filter: %w", err)
			}
			if err := sj.journal.AddDisjunction(); err != nil {
				return nil, nil, err
			}
			if err := sj.journal.AddMatch("_SYSTEMD_UNIT=" + firstUnit); err != nil {
				return nil, nil, fmt.Errorf("failed to add unit filter: %w", err)
			}
			if err := sj.journal.AddConjunction(); err != nil {
				return nil, nil, err
			}
		}
	}
	if !params.AllBoots {
		if bootId, err := sj.journal.GetBootID(); err != nil {
			return nil, nil, fmt.Errorf("failed to get boot id: %s", err)
		} else if err := sj.journal.AddMatch("_BOOT_ID=" + bootId); err != nil {
			return nil, nil, fmt.Errorf("failed to add boot filter: %w", err)
		}
	}

	// Handle time-based filtering
	if !params.From.IsZero() || !params.To.IsZero() {
		err = sj.seekByTimeRange(params)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// Use original pagination logic when no time filters
		_, err = sj.seekAndSkip(uint64(params.Count), uint64(params.Offset))
		if err != nil {
			return nil, nil, err
		}
	}

	var messages []LogOutput
	uniqIdentifiers := make(map[string]bool)
	uniqIdentifiersStr := ""
	uniqUnitName := make(map[string]bool)
	uniqUnitNameStr := ""
	uniqExeName := make(map[string]bool)
	host, _ := os.Hostname()

	var regexPattern *regexp.Regexp
	if params.Pattern != "" {
		var err error
		regexPattern, err = regexp.Compile(params.Pattern)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	collectedCount := 0
	maxCount := params.Count
	if maxCount <= 0 {
		maxCount = 100
	}

	for {
		entry, err := sj.journal.GetEntry()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get log entry for %v", params.Unit)
		}

		timestamp := time.Unix(0, int64(entry.RealtimeTimestamp)*int64(time.Microsecond))

		if !params.To.IsZero() && timestamp.Before(params.To) {

			ret, err := sj.journal.Next()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read next entry: %w", err)
			}
			if ret == 0 {
				break
			}
			continue
		}

		if !params.From.IsZero() && timestamp.After(params.From) {
			ret, err := sj.journal.Next()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read next entry: %w", err)
			}
			if ret == 0 {
				break
			}
			continue
		}

		if regexPattern != nil {
			var messages strings.Builder
			for _, v := range entry.Fields {
				messages.WriteString(v)
			}
			if !regexPattern.MatchString(messages.String()) {
				ret, err := sj.journal.Next()
				if err != nil {
					return nil, nil, fmt.Errorf("failed to read next entry: %w", err)
				}
				if ret == 0 {
					break
				}
				continue
			}
		}

		structEntr := LogOutput{
			Identifier: entry.Fields["SYSLOG_IDENTIFIER"],
			UnitName:   entry.Fields["_SYSTEMD_UNIT"],
			ExeName:    entry.Fields["_EXE"],
			Time:       timestamp,
			Msg:        entry.Fields["MESSAGE"],
		}
		if _, ok := uniqIdentifiers[entry.Fields["SYSLOG_IDENTIFIER"]]; !ok {
			uniqIdentifiers[entry.Fields["SYSLOG_IDENTIFIER"]] = true
			uniqIdentifiersStr = entry.Fields["SYSLOG_IDENTIFIER"]
		}
		if _, ok := uniqUnitName[entry.Fields["_SYSTEMD_UNIT"]]; !ok {
			uniqUnitName[entry.Fields["_SYSTEMD_UNIT"]] = true
			uniqUnitNameStr = entry.Fields["_SYSTEMD_UNIT"]
		}
		if entry.Fields["_EXE"] != "" {
			if _, ok := uniqExeName[entry.Fields["_EXE"]]; !ok {
				uniqExeName[entry.Fields["_EXE"]] = true
			}
		}
		if params.AllBoots {
			structEntr.Boot = entry.Fields["_BOOT_ID"]
		}
		if host == entry.Fields["_HOSTNAME"] {
			host = entry.Fields["_HOSTNAME"]
		}
		if structEntr.Identifier == "" {
			structEntr.Identifier = fmt.Sprintf("%s:%s", entry.Fields["_SYSTEMD_UNIT"], entry.Fields["_SYSTEMD_USER_UNIT"])
		}
		messages = append(messages, structEntr)
		collectedCount++

		if collectedCount >= maxCount {
			break
		}

		ret, err := sj.journal.Next()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read next entry: %w", err)
		}
		if ret == 0 {
			break
		}
	}

	res := ListLogResult{
		Host:       host,
		NrMessages: len(messages),
		Messages:   messages,
	}
	if len(uniqIdentifiers) == 1 {
		res.Identifier = uniqIdentifiersStr
		for i := range messages {
			messages[i].Identifier = ""
		}
	}
	if len(uniqUnitName) == 1 {
		res.UnitName = uniqUnitNameStr
		for i := range messages {
			messages[i].UnitName = ""
		}
	}
	if len(params.Unit) > 0 {
		for exe := range uniqExeName {
			if exe == "" {
				continue
			}
			cmd := exec.Command("rpm", "-qdf", exe)
			var out bytes.Buffer
			cmd.Stdout = &out
			err := cmd.Run()
			if err != nil {
				slog.Debug("rpm command failed", "exe", exe, "err", err)
				continue
			}

			docLines := make(map[string]bool)
			for _, doc := range strings.Split(out.String(), "\n") {
				if ok := docLines[doc]; !ok {
					docLines[doc] = true
				}
			}

			// for splitting the output of man -f
			reMan := regexp.MustCompile(`^(\S+)\s+\(([^)]+)\)\s+-\s+(.*)$`)
			for name := range docLines {
				if !strings.Contains(name, "/man/man") {
					continue
				}
				manPageFile := filepath.Base(name)
				cmdMan := exec.Command("man", "-f", strings.Split(manPageFile, ".")[0])
				var outMan bytes.Buffer
				cmdMan.Stdout = &outMan
				if err := cmdMan.Run(); err != nil {
					slog.Debug("man command failed", "name", name, "err", err)
					continue
				}
				for _, line := range strings.Split(strings.TrimSpace(outMan.String()), "\n") {
					matches := reMan.FindStringSubmatch(line)
					if len(matches) == 4 {
						secStr := matches[2]
						// Validate section contains only alphanumeric characters
						if !validManSection.MatchString(secStr) {
							continue
						}

						res.Documentation = append(res.Documentation, ManPage{
							Name:        matches[1],
							Section:     secStr,
							Description: matches[3],
						})
					}
				}
			}
		}
	}

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
