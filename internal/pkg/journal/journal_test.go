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

func TestListLogForTimeRangeWithoutUnit(t *testing.T) {
	now := time.Now()
	from := now.Add(-10 * time.Minute)
	to := now.Add(5 * time.Minute)

	sj := &HostLog{
		Auth: unregisteredAuth{},
	}

	res, _, err := sj.ListLog(context.Background(), nil, &ListLogParams{
		Count:    10,
		From:     journalTime(from),
		To:       journalTime(to),
		AllBoots: true,
	})
	require.NoError(t, err, "getting logs for a time range without a unit must not fail")
	require.NotNil(t, res)

	textContent, ok := res.Content[0].(*mcp.TextContent)
	require.Truef(t, ok, "expected a text content, got %T", res.Content[0])

	var result ListLogResult
	require.NoError(t, json.Unmarshal([]byte(textContent.Text), &result))
	require.NotEmptyf(t, result.Messages, "expected log entries in [%s .. %s]", from, to)
	assert.LessOrEqual(t, len(result.Messages), 10)
	for i := range result.Messages {
		m := &result.Messages[i]
		assert.Falsef(t, m.Time.Before(from), "entry %d at %s is before the from time %s", i, m.Time, from)
		assert.Truef(t, m.Time.Before(to), "entry %d at %s is after the to time %s", i, m.Time, to)
	}
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
