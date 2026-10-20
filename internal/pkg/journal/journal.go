package journal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/openSUSE/systemd-mcp/dbus"
	"github.com/openSUSE/systemd-mcp/internal/pkg/man"
	"github.com/openSUSE/systemd-mcp/internal/pkg/sdjournalw"
	"github.com/openSUSE/systemd-mcp/internal/pkg/util"
)

// how much of the journal the opened handle covers
type journalAccess int

const (
	accessNone       journalAccess = iota
	accessFull                     // every journal file, we are root or in the journal group
	accessGatekeeper               // every journal file, handed over by the polkit authorized gatekeeper
	accessUser                     // only the files the calling user may read, i.e. its own user-<uid>.journal
)

type HostLog struct {
	journal *sdjournal.Journal
	access  journalAccess
	Auth    auth.AuthKeeper
}

// Close the log and underlying journal
func (log *HostLog) Close() error {
	return log.journal.Close()
}

type ListLogParams struct {
	Host      string    `json:"host,omitempty" jsonschema:"Host on which to run this command. This always runs on the local machine (os.Hostname())."`
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
	inputSchema.Properties["host"].Default = json.RawMessage("\"localhost\"")
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

// position the read cursor before the first entry to be read when listing
// the newest entries of a time range. A seek leaves the cursor between two
// entries, so the first Previous/Next call after it is mandatory before any
// Get* call may be used.
func (sj *HostLog) seekByTimeRange(count uint64, offset uint64, from time.Time, to time.Time) (uint64, error) {
	// Validate time range
	if !from.IsZero() && !to.IsZero() {
		if from.After(to) {
			return 0, fmt.Errorf("from time cannot be after to time")
		}
	}

	if !to.IsZero() {
		toMicros := uint64(to.UnixNano() / 1000)
		if err := sj.journal.SeekRealtimeUsec(toMicros); err != nil {
			return 0, fmt.Errorf("failed to seek to time range: %w", err)
		}
	} else {
		if err := sj.journal.SeekTail(); err != nil {
			return 0, fmt.Errorf("failed to seek to end: %w", err)
		}
	}

	// move to the newest entry of the range
	if n, err := sj.journal.Previous(); err != nil {
		return 0, fmt.Errorf("failed to position on newest entry: %w", err)
	} else if n == 0 {
		return 0, nil
	}

	// Skip offset entries first
	if offset > 0 {
		if n, err := sj.journal.PreviousSkip(offset); err != nil {
			return 0, fmt.Errorf("failed to skip offset entries: %w", err)
		} else if n == 0 {
			return 0, nil
		}
	}

	if n, err := sj.journal.PreviousSkip(count); err != nil {
		return 0, fmt.Errorf("failed to move back entries: %w", err)
	} else if n == 0 {
		return 0, nil
	}

	return count, nil
}

func (sj *HostLog) isJournalGroupMember() bool {
	// with volatile storage the journal only lives in /run/log/journal
	info, err := os.Stat("/var/log/journal")
	if err != nil {
		if info, err = os.Stat("/run/log/journal"); err != nil {
			return false
		}
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

// ask the gatekeeper for the file descriptors of the journal files, which
// triggers a polkit call in the gatekeeper for the calling process
func (sj *HostLog) openViaGatekeeper() (*sdjournal.Journal, error) {
	addr, err := net.ResolveUnixAddr("unix", "/run/gatekeeper/gatekeeper.socket")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve gatekeeper socket: %w", err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gatekeeper: %w", err)
	}
	defer conn.Close()

	buf := make([]byte, 32)
	oob := make([]byte, syscall.CmsgSpace(256*4)) // space for 256 fds
	n, oobn, flags, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fmt.Errorf("failed to read from gatekeeper: %w", err)
	}

	if flags&syscall.MSG_CTRUNC != 0 {
		return nil, fmt.Errorf("gatekeeper sent too many file descriptors (control message truncated)")
	}

	if string(buf[:n]) != "OK\n" {
		return nil, fmt.Errorf("gatekeeper error: %s", strings.TrimSpace(string(buf[:n])))
	}

	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(cmsgs) == 0 {
		return nil, fmt.Errorf("no fds received from gatekeeper")
	}

	fds, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil || len(fds) == 0 {
		return nil, fmt.Errorf("no fds received from gatekeeper")
	}

	uintFds := make([]uintptr, len(fds))
	for i, fd := range fds {
		uintFds[i] = uintptr(fd)
	}

	j, err := sdjournalwarp.NewJournalFromHandle(uintFds)
	if err != nil {
		return nil, fmt.Errorf("failed to open journal from fd: %w", err)
	}
	return &j.Journal, nil
}

// sd_journal_open() silently skips every file the caller may not read and
// still reports success, so an opened journal can be completely empty. Check
// for at least one entry before using it as the fallback.
func hasEntries(j *sdjournal.Journal) bool {
	if err := j.SeekTail(); err != nil {
		return false
	}
	n, err := j.Previous()
	return err == nil && n > 0
}

// check several cases here:
//  1. we run as root or as a member of the journal group, so sd_journal_open()
//     gives us every journal file. Access is authorized via oauth2
//  2. we run as a normal user and get the file descriptors from the gatekeeper,
//     which triggers a polkit call
//  3. neither of both, but sd_journal_open() still opens all files which are
//     readable for the calling user, journald grants every user read access to
//     its own user-<uid>.journal via an ACL. So as a last resort we run with
//     the logs of the current user only
//
// Only want annoy the user with a oauth2 or polkit call only if access to the log is
// requested
// This isn't an ideal solution, but I couldn't think of a better one
func (sj *HostLog) self_init(ctx context.Context) (allowed bool, err error) {
	if sj.journal == nil {
		if os.Geteuid() == 0 || sj.isJournalGroupMember() {
			j, err := sdjournal.NewJournal()
			if err != nil {
				return false, fmt.Errorf("failed to open journal: %w", err)
			}
			sj.journal, sj.access = j, accessFull
		} else if j, gkErr := sj.openViaGatekeeper(); gkErr == nil {
			sj.journal, sj.access = j, accessGatekeeper
		} else {
			slog.Info("gatekeeper not usable, falling back to the journal files of the current user",
				slog.Any("error", gkErr))
			j, err := sdjournal.NewJournal()
			if err != nil {
				return false, fmt.Errorf("failed to open journal: %w (gatekeeper: %v)", err, gkErr)
			}
			if !hasEntries(j) {
				j.Close()
				return false, fmt.Errorf("no readable journal files: %w", gkErr)
			}
			sj.journal, sj.access = j, accessUser
		}
	}
	// the gatekeeper already asked polkit and members of the journal group may
	// read the journal anyway, so don't ask a second time
	if sj.access == accessGatekeeper || sj.isJournalGroupMember() {
		return true, nil
	}
	allowed, err = sj.Auth.IsReadAuthorized(ctx)
	// without the gatekeeper package polkit doesn't know its action at all. As
	// only the journal files of the calling user are open, which it may read
	// anyway, a missing policy mustn't block the access
	if err != nil && sj.access == accessUser && errors.Is(err, dbus.ErrActionNotRegistered) {
		slog.Info("no polkit policy for the journal, continuing with the logs of the current user",
			slog.Any("error", err))
		return true, nil
	}
	return allowed, err
}

// tell the caller if only a part of the journal is visible
func (sj *HostLog) accessHint() string {
	if sj.access != accessUser {
		return ""
	}
	return fmt.Sprintf("Only the journal files which are readable by the current user (uid %d) are "+
		"open, so entries of system units are missing. Run systemd-mcp as root, add the user to the "+
		"journal group or start the gatekeeper service to get access to the whole journal.", os.Geteuid())
}

func logResult(res ListLogResult) (*mcp.CallToolResult, any, error) {
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

// get the lat log entries for a given unit, else just the last messages
func (sj *HostLog) ListLog(ctx context.Context, req *mcp.CallToolRequest, params *ListLogParams) (*mcp.CallToolResult, any, error) {
	// 'localhost' is a synonym for the local machine, so resolve the effective host
	slog.Debug("ListLog called", "resolved_host", util.HostName(params.Host))
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
	maxCount := params.Count
	if maxCount <= 0 {
		maxCount = 100
	}
	if !params.From.IsZero() || !params.To.IsZero() {
		nrEntries, err := sj.seekByTimeRange(uint64(maxCount), uint64(params.Offset), params.From, params.To)
		if err != nil {
			return nil, nil, err
		}
		if nrEntries == 0 {
			// no entry in the range, the read head isn't on an entry so don't read one
			return logResult(ListLogResult{Host: util.LocalHostName(), Hint: sj.accessHint()})
		}
	} else {
		// Use original pagination logic when no time filters
		nrEntries, err := sj.seekAndSkip(uint64(params.Count), uint64(params.Offset))
		if err != nil {
			return nil, nil, err
		}
		if nrEntries == 0 {
			// nothing matched, the read head isn't on an entry so don't read one
			return logResult(ListLogResult{Host: util.LocalHostName(), Hint: sj.accessHint()})
		}
	}

	var messages []LogOutput
	uniqIdentifiers := make(map[string]bool)
	uniqIdentifiersStr := ""
	uniqUnitName := make(map[string]bool)
	uniqUnitNameStr := ""
	uniqExeName := make(map[string]bool)
	host := util.LocalHostName()

	var regexPattern *regexp.Regexp
	if params.Pattern != "" {
		var err error
		regexPattern, err = regexp.Compile(params.Pattern)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	collectedCount := 0

	for {
		entry, err := sj.journal.GetEntry()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get log entry for %v", params.Unit)
		}

		timestamp := time.Unix(0, int64(entry.RealtimeTimestamp)*int64(time.Microsecond))

		// we scan forward from the newest entry of the range, so once we run
		// into an entry older than the start of the range the scan is done
		if !params.From.IsZero() && timestamp.Before(params.From) {
			break
		}

		if regexPattern != nil {
			var allFields strings.Builder
			for _, v := range entry.Fields {
				allFields.WriteString(v)
			}
			if !regexPattern.MatchString(allFields.String()) {
				// not collected, keep the same budget of entries to scan
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
		Hint:       sj.accessHint(),
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

	return logResult(res)
}
