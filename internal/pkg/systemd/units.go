package systemd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/openSUSE/systemd-mcp/dbus"
	"github.com/openSUSE/systemd-mcp/internal/pkg/util"
)

func ValidStates() []string {
	return []string{"active", "inactive", "loaded", "not-found", "all", "failed"}
}

func ValidUnitFileStates() []string {
	return []string{"enabled", "enabled-runtime", "linked", "linked-runtime", "masked", "masked-runtime", "static", "disabled", "invalid", "all"}
}

type UnitProperties struct {
	Id          string `json:"Id"`
	Description string `json:"Description"`

	// Load state info
	LoadState      string `json:"LoadState"`
	FragmentPath   string `json:"FragmentPath"`
	UnitFileState  string `json:"UnitFileState"`
	UnitFilePreset string `json:"UnitFilePreset"`

	// Active state info
	ActiveState          string `json:"ActiveState"`
	SubState             string `json:"SubState"`
	ActiveEnterTimestamp uint64 `json:"ActiveEnterTimestamp"`

	// Process info
	InvocationID   string `json:"InvocationID"`
	MainPID        int    `json:"MainPID"`
	ExecMainPID    int    `json:"ExecMainPID"`
	ExecMainStatus int    `json:"ExecMainStatus"`

	// Resource usage
	TasksCurrent uint64 `json:"TasksCurrent"`
	TasksMax     uint64 `json:"TasksMax"`
	CPUUsageNSec uint64 `json:"CPUUsageNSec"`

	// Control group
	ControlGroup string `json:"ControlGroup"`

	// Exec commands (simplified - would need additional processing)
	ExecStartPre [][]interface{} `json:"ExecStartPre"`
	ExecStart    [][]interface{} `json:"ExecStart"`

	// Additional fields that might be useful
	Restart       string `json:"Restart"`
	MemoryCurrent uint64 `json:"MemoryCurrent"`
}

type ListLoadedUnitsParams struct {
	Host               string   `json:"host,omitempty" jsonschema:"Host on which to run this command. 'localhost' (the default) is a synonym for the local machine (os.Hostname()); any other value must be a host registered via the set_host tool."`
	State              string   `json:"state,omitempty" jsonschema:"List units in this active/load state (e.g. 'active', 'failed'). Defaults to 'active'. Use 'all' to list all states. Note: SubStates like 'running', 'dead', 'mounted', 'plugged' are not supported - use the corresponding parent ActiveState instead (e.g., 'active' for running units, 'inactive' for dead units)."`
	Patterns           []string `json:"patterns,omitempty" jsonschema:"List units by their names or patterns (e.g. '*.service')."`
	Properties         bool     `json:"properties,omitempty" jsonschema:"If true, return detailed properties for each unit."`
	IncludeDescription bool     `json:"include_description,omitempty" jsonschema:"If true, include the description for each unit."`
	Verbose            bool     `json:"verbose,omitempty" jsonschema:"Return more details in the response."`
}

func CreateListLoadedUnitsSchema() *jsonschema.Schema {
	inputSchema, _ := jsonschema.For[ListLoadedUnitsParams](nil)
	var states []any
	for _, s := range ValidStates() {
		states = append(states, s)
	}

	if inputSchema.Properties["host"] != nil {
		inputSchema.Properties["host"].Default = json.RawMessage("\"localhost\"")
	}
	if inputSchema.Properties["state"] != nil {
		inputSchema.Properties["state"].Enum = states
		inputSchema.Properties["state"].Default = json.RawMessage("\"active\"")
	}

	return inputSchema
}

func (conn *Connection) ListLoadedUnits(ctx context.Context, req *mcp.CallToolRequest, params *ListLoadedUnitsParams) (*mcp.CallToolResult, any, error) {
	slog.Debug("ListLoadedUnits called", "params", params)
	if allowed, err := conn.auth.IsReadAuthorized(ctx); err != nil {
		return nil, nil, err
	} else if !allowed {
		return nil, nil, fmt.Errorf("calling method was canceled by user")
	}
	host := params.Host

	var reqStates []string

	if params.State == "all" {
		// List all states
		reqStates = []string{}
	} else if params.State != "" {
		reqStates = []string{params.State}
	} else {
		// Default to active units when no state is specified
		reqStates = []string{"active"}
	}

	return conn.withConn(ctx, host, func(dc DbusConnection, _ chan string) (*mcp.CallToolResult, any, error) {
		units, err := dc.ListUnitsByPatternsContext(ctx, reqStates, params.Patterns)
		if err != nil {
			return nil, nil, err
		}

		txtContentList := []mcp.Content{}

		if params.Properties {
			for _, u := range units {
				props, err := dc.GetAllPropertiesContext(ctx, u.Name)
				if err != nil {
					slog.Warn("failed to get properties for unit", "unit", u.Name, "error", err)
					continue
				}
				props = util.ClearMap(props)

				var jsonByte []byte
				if params.Verbose {
					jsonByte, err = EncodeWithHost(conn.Encoder, host, &props)
				} else {
					prop := UnitProperties{}
					tmp, _ := json.Marshal(props)
					if err := json.Unmarshal(tmp, &prop); err != nil {
						slog.Warn("failed to unmarshal properties", "unit", u.Name, "error", err)
						continue
					}
					jsonByte, err = EncodeWithHost(conn.Encoder, host, &prop)
				}
				if err != nil {
					return nil, nil, err
				}
				txtContentList = append(txtContentList, &mcp.TextContent{
					Text: string(jsonByte),
				})
			}
		} else if params.Verbose {
			for _, u := range units {
				jsonByte, err := EncodeWithHost(conn.Encoder, host, &u)
				if err != nil {
					return nil, nil, err
				}
				txtContentList = append(txtContentList, &mcp.TextContent{
					Text: string(jsonByte),
				})
			}
		} else {
			groups := make(map[string][]any)
			for _, u := range units {
				var unitData any
				if params.IncludeDescription {
					unitData = struct {
						Name        string `json:"name"`
						Description string `json:"description"`
					}{Name: u.Name, Description: u.Description}
				} else {
					unitData = u.Name
				}
				groups[u.ActiveState] = append(groups[u.ActiveState], unitData)
			}

			// Sort keys for consistent output
			states := make([]string, 0, len(groups))
			for s := range groups {
				states = append(states, s)
			}
			slices.Sort(states)

			for _, state := range states {
				res := struct {
					Host  string `json:"host"`
					State string `json:"state"`
					Units any    `json:"units"`
				}{Host: effectiveHost(host), State: state, Units: groups[state]}
				jsonByte, err := conn.Encoder.Encode(res)
				if err != nil {
					return nil, nil, err
				}
				txtContentList = append(txtContentList, &mcp.TextContent{
					Text: string(jsonByte),
				})
			}
		}

		if len(txtContentList) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: hostOnly(host)}},
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: txtContentList,
		}, nil, nil
	})
}

type ListUnitFilesParams struct {
	Host               string   `json:"host,omitempty" jsonschema:"Host on which to run this command. 'localhost' (the default) is a synonym for the local machine (os.Hostname()); any other value must be a host registered via the set_host tool."`
	State              string   `json:"state,omitempty" jsonschema:"List unit files in this enablement state (e.g. 'enabled', 'disabled'). Defaults to 'enabled'. Use 'all' to list all states."`
	Patterns           []string `json:"patterns,omitempty" jsonschema:"List unit files by their names or patterns (e.g. '*.service'). If empty all unit file are listed."`
	IncludeDescription bool     `json:"include_description,omitempty" jsonschema:"If true, include the description for each unit."`
}

func CreateListUnitFilesSchema() *jsonschema.Schema {
	inputSchema, _ := jsonschema.For[ListUnitFilesParams](nil)
	var states []any
	for _, s := range ValidUnitFileStates() {
		states = append(states, s)
	}

	if inputSchema.Properties["host"] != nil {
		inputSchema.Properties["host"].Default = json.RawMessage("\"localhost\"")
	}
	if inputSchema.Properties["state"] != nil {
		inputSchema.Properties["state"].Enum = states
		inputSchema.Properties["state"].Default = json.RawMessage("\"enabled\"")
	}

	return inputSchema
}

func (conn *Connection) ListUnitFiles(ctx context.Context, req *mcp.CallToolRequest, params *ListUnitFilesParams) (*mcp.CallToolResult, any, error) {
	slog.Debug("ListUnitFiles called", "params", params)
	if allowed, err := conn.auth.IsReadAuthorized(ctx); err != nil {
		return nil, nil, err
	} else if !allowed {
		return nil, nil, fmt.Errorf("calling method was canceled by user")
	}
	host := params.Host

	return conn.withConn(ctx, host, func(dc DbusConnection, _ chan string) (*mcp.CallToolResult, any, error) {
		unitList, err := dc.ListUnitFilesContext(ctx)
		if err != nil {
			return nil, nil, err
		}

		txtContentList := []mcp.Content{}
		// Prepare filters
		filterPatterns := len(params.Patterns) > 0

		groups := make(map[string][]any)

		for _, unit := range unitList {
			name := path.Base(unit.Path)
			state := unit.Type // In ListUnitFiles, Type corresponds to enablement state

			// Filter by state
			filterState := params.State
			if filterState == "" {
				// Default to enabled when no state is specified
				filterState = "enabled"
			}
			if filterState != "all" {
				if filterState != state {
					continue
				}
			}

			// Filter by pattern
			if filterPatterns {
				matched := false
				for _, pat := range params.Patterns {
					if match, _ := path.Match(pat, name); match {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
			}

			var unitData any
			if params.IncludeDescription {
				description := ""
				props, err := dc.GetAllPropertiesContext(ctx, name)
				if err == nil {
					if d, ok := props["Description"].(string); ok {
						description = d
					}
				}
				unitData = struct {
					Name        string `json:"name"`
					Description string `json:"description"`
				}{Name: name, Description: description}
			} else {
				unitData = name
			}
			groups[state] = append(groups[state], unitData)
		}

		// Sort keys for consistent output
		states := make([]string, 0, len(groups))
		for s := range groups {
			states = append(states, s)
		}
		slices.Sort(states)

		for _, state := range states {
			res := struct {
				Host  string `json:"host"`
				State string `json:"state"`
				Units any    `json:"units"`
			}{Host: effectiveHost(host), State: state, Units: groups[state]}
			jsonByte, err := json.Marshal(res)
			if err != nil {
				return nil, nil, fmt.Errorf("could not unmarshall result: %w", err)
			}
			txtContentList = append(txtContentList, &mcp.TextContent{
				Text: string(jsonByte),
			})
		}
		if len(txtContentList) == 0 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: hostOnly(host)}},
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: txtContentList,
		}, nil, nil
	})
}

// helper function to get the valid states
func (conn *Connection) ListStatesHandler(ctx context.Context) (lst []string, err error) {
	units, err := conn.dbus.ListUnitsByPatternsContext(ctx, []string{}, []string{})
	if err != nil {
		return
	}
	states := make(map[string]bool)
	for _, u := range units {
		if _, ok := states[u.ActiveState]; !ok {
			states[u.ActiveState] = true
		}
		if _, ok := states[u.LoadState]; !ok {
			states[u.LoadState] = true
		}
		if _, ok := states[u.SubState]; !ok {
			states[u.SubState] = true
		}
	}
	for key := range states {
		lst = append(lst, key)
	}
	return
}

type RestartReloadParams struct {
	Host         string `json:"host,omitempty" jsonschema:"Host on which to run this command. 'localhost' (the default) is a synonym for the local machine (os.Hostname()); any other value must be a host registered via the set_host tool."`
	Name         string `json:"name" jsonschema:"Exact name of unit to restart"`
	TimeOut      uint   `json:"timeout,omitempty" jsonschema:"Time to wait for the restart or reload to finish. After the timeout the function will return and restart and reload will run in the background and the result can be retreived with a separate function."`
	Mode         string `json:"mode,omitempty" jsonschema:"Mode used for the restart or reload. 'replace' should be used."`
	Forcerestart bool   `json:"forcerestart,omitempty" jsonschema:"mode of the operation. 'replace' should be used per default and replace allready queued jobs. With 'fail' the operation will fail if other operations are in progress."`
}

// return which are define in the upstream documentation as:
func ValidRestartModes() []string {
	return []string{"replace", "fail", "isolate", "ignore-dependencies", "ignore-requirements"}
}

const MaxTimeOut uint = 60

func GetRestsartReloadParamsSchema() *jsonschema.Schema {
	schema, _ := jsonschema.For[RestartReloadParams](nil)
	validList := []any{}
	for _, s := range ValidRestartModes() {
		validList = append(validList, any(s))
	}
	schema.Properties["mode"].Enum = validList
	if schema.Properties["host"] != nil {
		schema.Properties["host"].Default = json.RawMessage("\"localhost\"")
	}
	return schema
}

type CheckReloadRestartParams struct {
	TimeOut uint `json:"timeout,omitempty" jsonschema:"Time to wait for the restart or reload to finish. After the timeout the function will return and restart and reload will run in the background and the result can be retreived with a separate function."`
}

// check status of reload or restart
func (conn *Connection) CheckForRestartReloadRunning(ctx context.Context, req *mcp.CallToolRequest, params *RestartReloadParams) (res *mcp.CallToolResult, _ any, err error) {
	slog.Debug("CheckForRestartReloadRunning called", "params", params)
	host := params.Host

	allowed, err := conn.auth.IsWriteAuthorized(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !allowed {
		return nil, nil, fmt.Errorf("calling method was canceled by user")
	}
	select {
	case result := <-conn.rchannel:
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: hostMessage(host, result),
				},
			},
		}, nil, nil
	case <-time.After(3 * time.Second):
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: hostMessage(host, "Reload or restart still in progress."),
				},
			},
		}, nil, nil
	default:
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: hostMessage(host, "Finished"),
				},
			},
		}, nil, nil
	}
}

type ChangeUnitStateParams struct {
	Host    string `json:"host,omitempty" jsonschema:"Host on which to run this command. 'localhost' (the default) is a synonym for the local machine (os.Hostname()); any other value must be a host registered via the set_host tool."`
	Name    string `json:"name" jsonschema:"Exact name of unit to change state"`
	Action  string `json:"action" jsonschema:"Action to perform."`
	Mode    string `json:"mode,omitempty" jsonschema:"Mode when restarting a unit. Defaults to 'replace'."`
	TimeOut uint   `json:"timeout,omitempty" jsonschema:"Time to wait for the operation to finish. Max 60s."`
	Runtime bool   `json:"runtime,omitempty" jsonschema:"Enable/Disable only temporarily (runtime)."`
}

func ValidChanges() []string {
	return []string{"restart", "restart_force", "start", "stop", "stop_kill", "reload", "enable", "enable_force", "disable"}
}

func ValidModes() []string {
	return []string{"replace", "fail", "isolate", "ignore-dependencies", "ignore-requirements"}
}

func CreateChangeInputSchema() *jsonschema.Schema {
	inputSchmema, _ := jsonschema.For[ChangeUnitStateParams](nil)
	var states []any
	var modes []any
	for _, s := range ValidChanges() {
		states = append(states, s)
	}
	for _, m := range ValidModes() {
		modes = append(modes, m)
	}
	inputSchmema.Properties["action"].Enum = states
	inputSchmema.Properties["action"].Default = json.RawMessage("\"enable\"")
	inputSchmema.Properties["mode"].Enum = modes
	inputSchmema.Properties["mode"].Default = json.RawMessage("\"replace\"")
	inputSchmema.Properties["timeout"].Default = json.RawMessage("30")
	if inputSchmema.Properties["host"] != nil {
		inputSchmema.Properties["host"].Default = json.RawMessage("\"localhost\"")
	}

	return inputSchmema
}

func (conn *Connection) ChangeUnitState(ctx context.Context, req *mcp.CallToolRequest, params *ChangeUnitStateParams) (res *mcp.CallToolResult, _ any, err error) {
	host := params.Host
	slog.Debug("ChangeUnitState called", "params", params, "resolved_host", host)

	var permission string
	if params.Action == "enable" || params.Action == "enable_force" || params.Action == "disable" {
		permission = "org.freedesktop.systemd1.manage-unit-files"
	} else {
		permission = "org.freedesktop.systemd1.manage-units"
	}

	allowed, err := conn.auth.IsWriteAuthorized(context.WithValue(ctx, dbus.PermissionKey, permission))
	if !allowed || err != nil {
		slog.Debug("ChangeUnit wasn't authorized", "reason", err)
		return nil, nil, fmt.Errorf("calling method wasn't authorized: %s", err)
	}
	defer conn.auth.Deauthorize()

	if params.TimeOut > MaxTimeOut {
		return nil, nil, fmt.Errorf("not waiting longer than MaxTimeOut(%d), longer operation will run in the background and result can be gathered with separate function.", MaxTimeOut)
	}

	if host == "" || host == LocalHost {
		host = LocalHost
	}

	return conn.withConn(ctx, host, func(dc DbusConnection, ch chan string) (*mcp.CallToolResult, any, error) {
		switch params.Action {
		case "start":
			if params.Mode == "" {
				params.Mode = "replace"
			}
			if !slices.Contains(ValidRestartModes(), params.Mode) {
				return nil, nil, fmt.Errorf("invalid mode for start: %s", params.Mode)
			}
			_, err = dc.StartUnitContext(ctx, params.Name, params.Mode, ch)
		case "stop":
			_, err = dc.StopUnitContext(ctx, params.Name, params.Mode, ch)
		case "stop_kill":
			dc.KillUnitContext(ctx, params.Name, int32(9))
		case "restart_force":
			_, err = dc.RestartUnitContext(ctx, params.Name, params.Mode, ch)
		case "restart":
			_, err = dc.ReloadOrRestartUnitContext(ctx, params.Name, params.Mode, ch)
		case "reload":
			_, err = dc.ReloadOrRestartUnitContext(ctx, params.Name, params.Mode, ch)
		case "enable", "enable_force":
			_, enabledRes, err := dc.EnableUnitFilesContext(ctx, []string{params.Name}, params.Runtime, strings.HasSuffix(params.Action, "_force"))
			if err != nil {
				slog.Error("error when enabling", "dbus.error", err)
				return nil, nil, fmt.Errorf("error when enabling: %w", err)
			}
			if len(enabledRes) == 0 {
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						&mcp.TextContent{Text: hostMessage(host, fmt.Sprintf("nothing changed for %s", params.Name))},
					},
				}, nil, nil
			}
			txtContentList := []mcp.Content{}
			for _, res := range enabledRes {
				resJson := struct {
					Host        string `json:"host"`
					Type        string `json:"type"`
					Filename    string `json:"filename"`
					Destination string `json:"destination"`
				}{Host: effectiveHost(host), Type: res.Type, Filename: res.Filename, Destination: res.Destination}
				jsonByte, _ := json.Marshal(resJson)
				txtContentList = append(txtContentList, &mcp.TextContent{Text: string(jsonByte)})
			}
			return &mcp.CallToolResult{Content: txtContentList}, nil, nil
		case "disable":
			disabledRes, err := dc.DisableUnitFilesContext(ctx, []string{params.Name}, params.Runtime)
			if err != nil {
				return nil, nil, fmt.Errorf("error when disabling: %w", err)
			}
			if len(disabledRes) == 0 {
				return &mcp.CallToolResult{
					Content: []mcp.Content{
						&mcp.TextContent{Text: hostMessage(host, fmt.Sprintf("nothing changed for %s", params.Name))},
					},
				}, nil, nil
			}
			txtContentList := []mcp.Content{}
			for _, res := range disabledRes {
				resJson := struct {
					Host        string `json:"host"`
					Type        string `json:"type"`
					Filename    string `json:"filename"`
					Destination string `json:"destination"`
				}{Host: effectiveHost(host), Type: res.Type, Filename: res.Filename, Destination: res.Destination}
				jsonByte, _ := json.Marshal(resJson)
				txtContentList = append(txtContentList, &mcp.TextContent{Text: string(jsonByte)})
			}
			return &mcp.CallToolResult{Content: txtContentList}, nil, nil
		default:
			return nil, nil, fmt.Errorf("invalid action: %s", params.Action)
		}

		if err != nil {
			return nil, nil, err
		}

		select {
		case result := <-ch:
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{
						Text: hostMessage(host, result),
					},
				},
			}, nil, nil
		case <-time.After(3 * time.Second):
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{
						Text: hostMessage(host, "Reload or restart still in progress."),
					},
				},
			}, nil, nil
		default:
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{
						Text: hostMessage(host, "Finished"),
					},
				},
			}, nil, nil
		}
	})
}
