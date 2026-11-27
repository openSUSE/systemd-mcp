package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
	godbus "github.com/godbus/dbus/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openSUSE/systemd-mcp/dbus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateListLogsSchema(t *testing.T) {
	schema := CreateListLogsSchema()
	assert.NotNil(t, schema)
	assert.Contains(t, schema.Properties, "count")
	assert.Contains(t, schema.Properties, "offset")
	assert.Contains(t, schema.Properties, "unit")
	assert.Contains(t, schema.Properties, "from")
	assert.Contains(t, schema.Properties, "to")
}

func TestParseTimeRelative(t *testing.T) {
	now := time.Now()

	cases := []struct {
		in   string
		want time.Time
		tol  time.Duration
	}{
		{"6h", now.Add(-6 * time.Hour), 2 * time.Second},
		{"1d", now.Add(-24 * time.Hour), 5 * time.Second},
		{"90m", now.Add(-90 * time.Minute), 2 * time.Second},
		{"-6h", now.Add(-6 * time.Hour), 2 * time.Second},
		{"-1d", now.Add(-24 * time.Hour), 5 * time.Second},
		{"+1d", now.Add(24 * time.Hour), 5 * time.Second},
		{"now", now, 5 * time.Second},
		{"100ms", now.Add(-100 * time.Millisecond), 50 * time.Millisecond},
		{"-3d12h", now.Add(-3*24*time.Hour - 12*time.Hour), 5 * time.Second},
	}
	for _, c := range cases {
		got, err := ParseTime(c.in)
		require.NoError(t, err, "ParseTime(%q)", c.in)
		assert.Truef(t, got.After(c.want.Add(-c.tol)) && got.Before(c.want.Add(c.tol)),
			"ParseTime(%q) = %s, want ~%s", c.in, got, c.want)
	}

	// sub-millisecond units are intentionally rejected
	for _, bad := range []string{"1ns", "500ns", "1us", "2500us", "-1ms1ns", "+1us"} {
		_, err := ParseTime(bad)
		require.Errorf(t, err, "ParseTime(%q) should reject sub-millisecond units", bad)
	}

	_, err := ParseTime("not-a-time")
	assert.Error(t, err)
}

func TestParseTimeFromJSON(t *testing.T) {
	s := struct {
		From journalTime `json:"from"`
		To   journalTime `json:"to"`
	}{}
	require.NoError(t, json.Unmarshal([]byte(`{"from":"6h","to":"+1d"}`), &s))
	assert.False(t, s.From.IsZero())
	assert.False(t, s.To.IsZero())
	now := time.Now()
	assert.Truef(t, s.From.Time().After(now.Add(-7*time.Hour)) && s.From.Time().Before(now.Add(-5*time.Hour)),
		"from should be ~now-6h, got %s", s.From.Time())
}

// an AuthKeeper which always fails as polkit doesn't know the action
type unregisteredAuth struct{}

func (unregisteredAuth) IsReadAuthorized(ctx context.Context) (bool, error) {
	return false, fmt.Errorf("%w: %s", dbus.ErrActionNotRegistered, "com.suse.gatekeeper.readlog")
}

func (unregisteredAuth) IsWriteAuthorized(ctx context.Context) (bool, error) {
	return false, fmt.Errorf("%w: %s", dbus.ErrActionNotRegistered, "com.suse.gatekeeper.readlog")
}

func (unregisteredAuth) Deauthorize() *godbus.Error { return nil }

func (unregisteredAuth) Close() error { return nil }

// testJournal is the synthetic journal created by testdata/make-test-journal.sh,
// see the script for the full list of entries
const testJournal = "testdata/test.journal"

var (
	testBoot1 = "11111111111111111111111111111111"
	testBoot2 = "22222222222222222222222222222222"
	// first entry of each boot, the entries follow in 10 second steps
	testBoot1Start = time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	testBoot2Start = time.Date(2026, 1, 2, 8, 0, 0, 0, time.UTC)
)

// newTestHostLog returns a HostLog reading the synthetic test journal. As the
// journal is already open, self_init doesn't search for the journal of the
// host, and accessUser lets the missing polkit policy pass
func newTestHostLog(t *testing.T) *HostLog {
	t.Helper()
	j, err := sdjournal.NewJournalFromFiles(testJournal)
	require.NoError(t, err, "opening %s, recreate it with testdata/make-test-journal.sh", testJournal)
	sj := &HostLog{journal: j, access: accessUser, Auth: unregisteredAuth{}}
	t.Cleanup(func() { sj.Close() })
	return sj
}

// listTestLog calls ListLog on the synthetic journal and decodes the result
func listTestLog(t *testing.T, params *ListLogParams) ListLogResult {
	t.Helper()
	res, _, err := newTestHostLog(t).ListLog(context.Background(), nil, params)
	require.NoError(t, err)
	require.NotNil(t, res)
	textContent, ok := res.Content[0].(*mcp.TextContent)
	require.Truef(t, ok, "expected a text content, got %T", res.Content[0])
	var result ListLogResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &result))
	return result
}

func messageTexts(result ListLogResult) []string {
	msgs := make([]string, len(result.Messages))
	for i := range result.Messages {
		msgs[i] = result.Messages[i].Msg
	}
	return msgs
}

func TestListLogForTimeRangeWithoutUnit(t *testing.T) {
	from := testBoot1Start.Add(15 * time.Second)
	to := testBoot1Start.Add(45 * time.Second)

	result := listTestLog(t, &ListLogParams{
		Count:    10,
		From:     journalTime(from),
		To:       journalTime(to),
		AllBoots: true,
	})
	require.Equal(t, []string{
		"(root) CMD (run-parts /etc/cron.hourly)",
		"Accepted publickey for tux from 192.0.2.10 port 50000 ssh2",
		"user application started",
	}, messageTexts(result))
	assert.Equal(t, len(result.Messages), result.NrMessages)
	for i := range result.Messages {
		m := &result.Messages[i]
		assert.Falsef(t, m.Time.Before(from), "entry %d at %s is before the from time %s", i, m.Time, from)
		assert.Truef(t, m.Time.Before(to), "entry %d at %s is after the to time %s", i, m.Time, to)
		assert.Equal(t, testBoot1, m.Boot)
	}
	assert.True(t, result.Messages[0].Time.Equal(testBoot1Start.Add(20*time.Second)))
}

func TestListLogForTimeRangeCount(t *testing.T) {
	// the newest two entries of the first boot
	result := listTestLog(t, &ListLogParams{
		Count:    2,
		From:     journalTime(testBoot1Start),
		To:       journalTime(testBoot1Start.Add(time.Minute)),
		AllBoots: true,
	})
	assert.Equal(t, []string{
		"user application started",
		"usb 1-1: new high-speed USB device",
	}, messageTexts(result))
}

func TestListLogForTimeRangeEdges(t *testing.T) {
	// the only entry of the range is the first entry of the journal
	result := listTestLog(t, &ListLogParams{
		Count:    10,
		From:     journalTime(testBoot1Start.Add(-time.Hour)),
		To:       journalTime(testBoot1Start.Add(5 * time.Second)),
		AllBoots: true,
	})
	assert.Equal(t, []string{"Started systemd-journald.service."}, messageTexts(result))

	// 'to' is exclusive, 'from' inclusive
	result = listTestLog(t, &ListLogParams{
		Count:    10,
		From:     journalTime(testBoot1Start.Add(10 * time.Second)),
		To:       journalTime(testBoot1Start.Add(30 * time.Second)),
		AllBoots: true,
	})
	assert.Equal(t, []string{
		"Server listening on 0.0.0.0 port 22.",
		"(root) CMD (run-parts /etc/cron.hourly)",
	}, messageTexts(result))

	// a range over both boots with the newest entries limited by count
	result = listTestLog(t, &ListLogParams{
		Count:    3,
		From:     journalTime(testBoot1Start.Add(40 * time.Second)),
		To:       journalTime(testBoot2Start.Add(15 * time.Second)),
		AllBoots: true,
	})
	assert.Equal(t, []string{
		"usb 1-1: new high-speed USB device",
		"Started systemd-journald.service.",
		"Server listening on 0.0.0.0 port 22.",
	}, messageTexts(result))
	require.Len(t, result.Messages, 3)
	assert.Equal(t, testBoot1, result.Messages[0].Boot)
	assert.Equal(t, testBoot2, result.Messages[2].Boot)
}

func TestListLogForTimeRangeWithoutEntries(t *testing.T) {
	result := listTestLog(t, &ListLogParams{
		Count:    10,
		From:     journalTime(testBoot1Start.Add(time.Hour)),
		To:       journalTime(testBoot1Start.Add(2 * time.Hour)),
		AllBoots: true,
	})
	assert.Empty(t, result.Messages)
	assert.Zero(t, result.NrMessages)
}

func TestListLogAllBoots(t *testing.T) {
	result := listTestLog(t, &ListLogParams{Count: 100, AllBoots: true})
	require.Len(t, result.Messages, 10)
	assert.Equal(t, testBoot1, result.Messages[0].Boot)
	assert.True(t, result.Messages[0].Time.Equal(testBoot1Start))
	assert.Equal(t, testBoot2, result.Messages[9].Boot)
	assert.True(t, result.Messages[9].Time.Equal(testBoot2Start.Add(30*time.Second)))
	// entries are returned in chronological order
	for i := 1; i < len(result.Messages); i++ {
		assert.Truef(t, result.Messages[i-1].Time.Before(result.Messages[i].Time),
			"entry %d is not older than entry %d", i-1, i)
	}
}

func TestListLogCountAndOffset(t *testing.T) {
	result := listTestLog(t, &ListLogParams{Count: 2, AllBoots: true})
	assert.Equal(t, []string{
		"(root) CMD (run-parts /etc/cron.daily)",
		"error: kex_exchange_identification: Connection closed by remote host",
	}, messageTexts(result))

	result = listTestLog(t, &ListLogParams{Count: 2, Offset: 2, AllBoots: true})
	assert.Equal(t, []string{
		"Started systemd-journald.service.",
		"Server listening on 0.0.0.0 port 22.",
	}, messageTexts(result))
	for i := range result.Messages {
		assert.Equal(t, testBoot2, result.Messages[i].Boot)
	}
}

func TestListLogUnitRegex(t *testing.T) {
	result := listTestLog(t, &ListLogParams{Count: 100, Unit: []string{"^sshd"}, AllBoots: true})
	assert.Equal(t, 4, result.NrMessages)
	// a single unit and identifier are reported once for the whole result
	assert.Equal(t, "sshd.service", result.UnitName)
	assert.Equal(t, "sshd", result.Identifier)
	for i := range result.Messages {
		assert.Empty(t, result.Messages[i].UnitName)
		assert.Empty(t, result.Messages[i].Identifier)
	}
}

func TestListLogExactUnit(t *testing.T) {
	result := listTestLog(t, &ListLogParams{Count: 100, Unit: []string{"cron.service"}, ExactUnit: true, AllBoots: true})
	assert.Equal(t, []string{
		"(root) CMD (run-parts /etc/cron.hourly)",
		"(root) CMD (run-parts /etc/cron.daily)",
	}, messageTexts(result))
	assert.Equal(t, "cron.service", result.UnitName)

	// the user unit is found via _SYSTEMD_USER_UNIT
	result = listTestLog(t, &ListLogParams{Count: 100, Unit: []string{"app.service"}, ExactUnit: true, AllBoots: true})
	assert.Equal(t, []string{"user application started"}, messageTexts(result))
}

func TestListLogUnknownUnit(t *testing.T) {
	result := listTestLog(t, &ListLogParams{Count: 100, Unit: []string{"^nonexistent"}, AllBoots: true})
	assert.Empty(t, result.Messages)
}

func TestListLogPattern(t *testing.T) {
	result := listTestLog(t, &ListLogParams{Count: 100, Pattern: "kex_exchange", AllBoots: true})
	require.Len(t, result.Messages, 1)
	assert.Equal(t, "sshd", result.Identifier)
	assert.Equal(t, testBoot2, result.Messages[0].Boot)
}

// without the gatekeeper package polkit can't grant its action, which must not
// block the journal files the calling user may read anyway
// stubRunner lets tests inject deterministic "remote" journalctl outputs
// without opening any SSH session.
type stubRunner struct {
	stdout string
	stderr string
	code   int
	err    error
}

func (s stubRunner) RunRemote(_ context.Context, _ *mcp.CallToolRequest, _, _ string) (string, string, int, error) {
	return s.stdout, s.stderr, s.code, s.err
}

func TestListLogRemoteUsesRunner(t *testing.T) {
	now := time.Now()
	jline := func(ts time.Time, msg, ident, unit string) string {
		b, _ := json.Marshal(map[string]string{
			"__REALTIME_TIMESTAMP": fmt.Sprintf("%d", ts.UnixNano()/1000),
			"MESSAGE":              msg,
			"SYSLOG_IDENTIFIER":    ident,
			"_SYSTEMD_UNIT":        unit,
		})
		return string(b)
	}
	stdout := jline(now, "hello", "app", "app.service") + "\n" +
		jline(now.Add(-time.Minute), "world", "app", "app.service") + "\n"

	sj := &HostLog{
		Auth:   unregisteredAuth{},
		Remote: stubRunner{stdout: stdout},
	}
	res, _, err := sj.ListLog(context.Background(), nil, &ListLogParams{
		Host:  "some-remote",
		Count: 10,
		Unit:  []string{"^app\\.service$"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	var out ListLogResult
	require.NoError(t, json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &out))
	assert.Equal(t, 2, out.NrMessages)
	assert.Equal(t, "some-remote", out.Host)
	assert.Equal(t, "app.service", out.UnitName)
}

func TestSelfInitWithoutPolkitPolicy(t *testing.T) {
	sj := &HostLog{journal: &sdjournal.Journal{}, Auth: unregisteredAuth{}}
	if sj.isJournalGroupMember() {
		t.Skip("running as a member of the journal group, no authorization needed")
	}

	sj.access = accessUser
	allowed, err := sj.self_init(context.Background())
	require.NoError(t, err)
	assert.True(t, allowed)

	// with the whole journal open the missing policy is a real error
	sj.access = accessFull
	allowed, err = sj.self_init(context.Background())
	assert.ErrorIs(t, err, dbus.ErrActionNotRegistered)
	assert.False(t, allowed)
}
