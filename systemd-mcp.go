package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	_ "embed"

	"github.com/cheynewallace/tabby"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/openSUSE/systemd-mcp/authkeeper"
	"github.com/openSUSE/systemd-mcp/internal/pkg/file"
	"github.com/openSUSE/systemd-mcp/internal/pkg/journal"
	"github.com/openSUSE/systemd-mcp/internal/pkg/man"
	"github.com/openSUSE/systemd-mcp/internal/pkg/systemd"
	"github.com/openSUSE/systemd-mcp/remoteauth"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	DBusName    = "org.opensuse.systemdmcp"
	DBusPath    = "/org/opensuse/systemdmcp"
	mcpPath     = "/mcp"
	magicNoauth = "ThisIsInsecure"
)

//go:embed VERSION
var version string

func systemdScopes() []string {
	return []string{"mcp:read"}
}

func NewRootCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:     "systemd-mcp",
		Short:   "Systemd MCP server",
		Version: strings.TrimSpace(version),
		RunE: func(cmd *cobra.Command, args []string) error {
			viper.SetEnvPrefix("SYSTEMD_MCP")
			viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
			viper.AutomaticEnv()
			viper.BindPFlags(cmd.Flags())

			logLevel := slog.LevelInfo
			if viper.GetBool("debug") {
				logLevel = slog.LevelDebug
			}
			handlerOpts := &slog.HandlerOptions{
				Level: logLevel,
			}
			var logger *slog.Logger
			logOutput := os.Stderr
			if viper.GetString("logfile") != "" {
				f, err := os.OpenFile(viper.GetString("logfile"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
				if err != nil {
					return fmt.Errorf("failed to open log file: %w", err)
				}
				defer f.Close()
				logOutput = f
			}

			// Choose handler based on format preference
			if viper.GetBool("log-json") {
				logger = slog.New(slog.NewJSONHandler(logOutput, handlerOpts))
			} else {
				logger = slog.New(slog.NewTextHandler(logOutput, handlerOpts))
			}
			slog.SetDefault(logger)
			slog.Debug("Logger initialized", "level", logLevel)

			var authorization authkeeper.AuthKeeper
			var err error

			isHttp := viper.GetString("http") != ""
			hasNoauth := viper.GetString("noauth") == magicNoauth
			hasController := viper.GetString("controller") != ""

			if isHttp && !hasNoauth && !hasController {
				return fmt.Errorf("http mode requires either --controller or --noauth=" + magicNoauth)
			}

			if hasNoauth {
				authorization, _ = authkeeper.NewNoAuth(true, true)
			} else if hasController {
				authorization, err = authkeeper.NewOauth(viper.GetString("controller"), viper.GetBool("skip-tls-verify"))
				if err != nil {
					return fmt.Errorf("couldn't create connection to controller: %w", err)
				}
			} else {
				authorization, err = authkeeper.NewPolkitAuth(DBusName, DBusPath, viper.GetUint32("timeout"))
				if err != nil {
					return fmt.Errorf("failed to setup dbus: %w", err)
				}
			}
			defer authorization.Close()

			server := mcp.NewServer(&mcp.Implementation{
				Name:    "Systemd connection",
				Version: strings.TrimSpace(version),
			},
				&mcp.ServerOptions{
					InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
						slog.Debug("Session started", "ID", req.Session.ID())
					},
				})
			systemConn, err := systemd.NewSystem(context.Background(), authorization)
			if err != nil {
				slog.Warn("couldn't add systemd tools", slog.Any("error", err))
			}

			tools := []struct {
				Tool     *mcp.Tool
				Register func(server *mcp.Server, tool *mcp.Tool)
			}{}

			if systemConn != nil {
				defer systemConn.Close()
				tools = append(tools,
					struct {
						Tool     *mcp.Tool
						Register func(server *mcp.Server, tool *mcp.Tool)
					}{
						Tool: &mcp.Tool{
							Title:       "List loaded units",
							Name:        "list_loaded_units",
							Description: fmt.Sprintf("List systemd units that are currently loaded in memory. Filter by states (%v) or patterns. Can return detailed properties.", systemd.ValidStates()),
							InputSchema: systemd.CreateListLoadedUnitsSchema(),
						},
						Register: func(server *mcp.Server, tool *mcp.Tool) {
							mcp.AddTool(server, tool, systemConn.ListLoadedUnits)
						},
					},
					struct {
						Tool     *mcp.Tool
						Register func(server *mcp.Server, tool *mcp.Tool)
					}{
						Tool: &mcp.Tool{
							Title:       "List unit files",
							Name:        "list_unit_files",
							Description: fmt.Sprintf("List all systemd unit files on disk. Filter by enablement states (%v) or patterns.", systemd.ValidUnitFileStates()),
							InputSchema: systemd.CreateListUnitFilesSchema(),
						},
						Register: func(server *mcp.Server, tool *mcp.Tool) {
							mcp.AddTool(server, tool, systemConn.ListUnitFiles)
						},
					},
					struct {
						Tool     *mcp.Tool
						Register func(server *mcp.Server, tool *mcp.Tool)
					}{
						Tool: &mcp.Tool{
							Title:       "Change unit state",
							Name:        "change_unit_state",
							Description: "Change the state of a unit or service (start, stop, restart, reload, enable, disable).",
							InputSchema: systemd.CreateChangeInputSchema(),
						},
						Register: func(server *mcp.Server, tool *mcp.Tool) {
							mcp.AddTool(server, tool, systemConn.ChangeUnitState)
						},
					},
					struct {
						Tool     *mcp.Tool
						Register func(server *mcp.Server, tool *mcp.Tool)
					}{
						Tool: &mcp.Tool{
							Title:       "Check restart/reload status",
							Name:        "check_restart_reload",
							Description: "Check the reload or restart status of a unit. Can only be called if the restart or reload job timed out.",
						},
						Register: func(server *mcp.Server, tool *mcp.Tool) {
							mcp.AddTool(server, tool, systemConn.CheckForRestartReloadRunning)
						},
					},
				)
			}
			syslog := journal.HostLog{
				Auth: authorization,
			}
			if err != nil {
				slog.Warn("couldn't open log, not adding journal tool", slog.Any("error", err))
			} else {
				tools = append(tools, struct {
					Tool     *mcp.Tool
					Register func(server *mcp.Server, tool *mcp.Tool)
				}{
					Tool: &mcp.Tool{
						Title:       "List system log",
						Name:        "list_log",
						Description: "Get the last log entries for the given service or unit.",
						InputSchema: journal.CreateListLogsSchema(),
					},
					Register: func(server *mcp.Server, tool *mcp.Tool) {
						mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, args *journal.ListLogParams) (*mcp.CallToolResult, any, error) {
							slog.Debug("list_log called", "args", args)
							res, out, err := syslog.ListLog(ctx, req, args)
							return res, out, err
						})
					},
				}, struct {
					Tool     *mcp.Tool
					Register func(server *mcp.Server, tool *mcp.Tool)
				}{
					Tool: &mcp.Tool{
						Title:       "Get content of file",
						Name:        "get_file",
						Description: "Read a file from the system. Can show content and metadata. Supports pagination for large files.",
						InputSchema: file.CreateFileSchema(),
					},
					Register: func(server *mcp.Server, tool *mcp.Tool) {
						mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, args *file.GetFileParams) (*mcp.CallToolResult, any, error) {
							slog.Debug("get_file called", "args", args)
							res, out, err := file.GetFile(ctx, req, args)
							return res, out, err
						})
					},
				})
			}
			tools = append(tools, struct {
				Tool     *mcp.Tool
				Register func(server *mcp.Server, tool *mcp.Tool)
			}{
				Tool: &mcp.Tool{
					Title:       "Display man page",
					Name:        "get_man_page",
					Description: "Retrieve a man page. Supports filtering by section and chapters, and pagination.",
					InputSchema: man.CreateManPageSchema(),
				},
				Register: func(server *mcp.Server, tool *mcp.Tool) {
					mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, args *man.GetManPageParams) (*mcp.CallToolResult, any, error) {
						slog.Debug("get_man_page called", "args", args)
						res, out, err := man.GetManPage(ctx, req, args)
						return res, out, err
					})
				},
			},
			)

			var allTools []string
			for _, tool := range tools {
				allTools = append(allTools, tool.Tool.Name)
			}
			if viper.GetBool("list-tools") {
				if viper.GetBool("verbose") {
					tb := tabby.New()
					tb.AddHeader("TOOL", "DESCRIPTION")
					for _, tool := range tools {
						tb.AddLine(tool.Tool.Name, tool.Tool.Description)
					}
					tb.Print()

				} else {
					fmt.Println(strings.Join(allTools, ","))
				}
				return nil
			}
			var enabledTools []string
			if !cmd.Flags().Changed("enabled-tools") {
				enabledTools = allTools
			} else {
				enabledTools = viper.GetStringSlice("enabled-tools")
			}
			// register the enabled tools
			for _, tool := range tools {
				if slices.Contains(enabledTools, tool.Tool.Name) {
					tool.Register(server, tool.Tool)
				}
			}

			if httpAddr := viper.GetString("http"); httpAddr != "" {
				handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
					return server
				}, nil)
				if hasNoauth {
					if viper.GetString("cert-file") == "" {
						slog.Debug("MCP handler listening at", slog.String("address", httpAddr))
						if err := http.ListenAndServe(httpAddr, handler); err != nil {
							slog.Error("couldn't start http server", "error", err)
						}
					} else {
						keyFile := viper.GetString("key-file")
						certFile := viper.GetString("cert-file")
						slog.Debug("MCP handler listening with TLS at", slog.String("address", httpAddr))
						if err := http.ListenAndServeTLS(httpAddr, certFile, keyFile, handler); err != nil {
							slog.Error("couldn't start tls http server", "error", err)
						}
					}
				} else {
					oauthProvider, ok := authorization.(authkeeper.OAuth2Provider)
					if !ok {
						return fmt.Errorf("authorization is not an OAuth2Provider")
					}
					authMiddleware := auth.RequireBearerToken(oauthProvider.VerifyJWT, &auth.RequireBearerTokenOptions{
						Scopes: systemdScopes(),
					})

					loggingMiddleware := func(next http.Handler) http.Handler {
						return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							authHeader := r.Header.Get("Authorization")
							slog.Debug("Received request at MCP endpoint",
								slog.String("path", r.URL.Path),
								slog.String("method", r.Method),
								slog.Bool("has_auth_header", authHeader != ""))
							next.ServeHTTP(w, r)
						})
					}

					http.HandleFunc(mcpPath, loggingMiddleware(authMiddleware(handler)).ServeHTTP)
					// handler for resourceMetaURL
					// TODO: replace with https://github.com/modelcontextprotocol/go-sdk/pull/643 after it's merged
					http.HandleFunc(remoteauth.DefaultProtectedResourceMetadataURI+mcpPath, func(w http.ResponseWriter, r *http.Request) {
						slog.Debug("Client requested OAuth metadata", slog.String("remote_addr", r.RemoteAddr))
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("Access-Control-Allow-Origin", "*")                     // for mcp-inspector
						w.Header().Set("Access-Control-Allow-Headers", "mcp-protocol-version") // for mcp-inspector
						prm := &oauthex.ProtectedResourceMetadata{
							AuthorizationServers:   []string{viper.GetString("controller")},
							ScopesSupported:        systemdScopes(),
							BearerMethodsSupported: []string{"header"},
							JWKSURI:                oauthProvider.JwksUri(),
						}
						slog.Debug("Sending OAuth protected resource metadata", slog.Any("metadata", prm))
						if err := json.NewEncoder(w).Encode(prm); err != nil {
							slog.Error("couldn't encode heaeder", "error", err)
						}
					})

					log.Print("MCP server listening on ", httpAddr+mcpPath)
					s := &http.Server{
						Addr:              httpAddr,
						ReadHeaderTimeout: 3 * time.Second,
					}
					if viper.GetString("cert-file") == "" {
						if err := s.ListenAndServe(); err != nil {
							slog.Error("couldn't start http server", "error", err)
						}
					} else {
						keyFile := viper.GetString("key-file")
						certFile := viper.GetString("cert-file")
						if err := s.ListenAndServeTLS(certFile, keyFile); err != nil {
							slog.Error("couldn't start tls http server", "error", err)
						}
					}
				}
			} else {
				slog.Debug("New client has connected via stdin/stdout")
				if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
					slog.Error("Server failed", slog.Any("error", err))
				}
			}

			return nil
		},
	}

	rootCmd.Flags().String("http", "", "if set, use streamable HTTP at this address, instead of stdin/stdout")
	rootCmd.Flags().Bool("skip-tls-verify", false, "Skip TLS certificate verification for outbound requests (e.g. to OAuth2 controller)")
	rootCmd.Flags().String("logfile", "", "if set, log to this file instead of stderr")
	rootCmd.Flags().String("controller", "", "oauth2 controller address")
	rootCmd.Flags().BoolP("verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().BoolP("debug", "d", false, "Enable debug logging")
	rootCmd.Flags().Bool("log-json", false, "Output logs in JSON format (machine-readable)")
	rootCmd.Flags().Bool("list-tools", false, "List all available tools and exit")
	rootCmd.Flags().BoolP("allow-write", "w", false, "Authorize write to systemd or allow pending write if started without write")
	rootCmd.Flags().BoolP("allow-read", "r", false, "Authorize read to systemd or allow pending read if started without read")
	rootCmd.Flags().StringSlice("enabled-tools", nil, "A list of tools to enable. Defaults to all tools.")
	rootCmd.Flags().Uint32("timeout", 5, "Set the timeout for authentication in seconds")
	rootCmd.Flags().String("noauth", "", fmt.Sprintf("Disable authorization via dbus/oauth2, this parameter has to be set to %s to work.", magicNoauth))
	rootCmd.Flags().String("cert-file", "", "Path to server certificate file (PEM format) for TLS. Requires --key-file")
	rootCmd.Flags().String("key-file", "", "Path to server private key file (PEM format) for TLS. Requires --cert-file")

	rootCmd.MarkFlagsRequiredTogether("cert-file", "key-file")
	rootCmd.MarkFlagsMutuallyExclusive("noauth", "controller")

	return rootCmd
}

func main() {
	rootCmd := NewRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
