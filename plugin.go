package traefik_plugin_geoblock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"log/slog"

	"github.com/ip2location/ip2location-go/v9"
)

//go:generate go run ./tools/dbdownload/main.go -o ./IP2LOCATION-LITE-DB1.IPV6.BIN

// Add this constant near the top of the file, after imports
const EmptyCountry = "-"

// Config defines the plugin configuration.
type Config struct {
	Enabled              bool     // Enable this plugin?
	DatabaseFilePath     string   // Path to ip2location database file
	AllowedCountries     []string // Whitelist of countries to allow (ISO 3166-1 alpha-2)
	BlockedCountries     []string // Blocklist of countries to be blocked (ISO 3166-1 alpha-2)
	DefaultAllow         bool     // If source matches neither blocklist nor whitelist, should it be allowed through?
	AllowPrivate         bool     // Allow requests from private / internal networks?
	DisallowedStatusCode int      // HTTP status code to return for disallowed requests
	BanHtmlFilePath      string   // Path to HTML file to serve for banned requests
	AllowedIPBlocks      []string // List of whitelist CIDR
	BlockedIPBlocks      []string // List of blocklisted CIDRs
	LogLevel             string   // "debug", "info", "warn", "error"
	LogFormat            string   // "json" or "text"
	LogPath              string   // Path to log file ("stdout", "stderr", or file path)
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		DisallowedStatusCode: http.StatusForbidden,
		LogLevel:             "error",  // Default to error logging
		LogFormat:            "text",   // Default to text format
		LogPath:              "stdout", // Default to stderr
	}
}

// Update the Plugin struct to store the ban HTML content instead of template
type Plugin struct {
	next                 http.Handler
	name                 string
	db                   *ip2location.DB
	enabled              bool
	allowedCountries     []string
	blockedCountries     []string
	defaultAllow         bool
	allowPrivate         bool
	disallowedStatusCode int
	banHtmlFilePath      string
	allowedIPBlocks      []*net.IPNet
	blockedIPBlocks      []*net.IPNet
	banHtmlContent       string // Changed from banHtmlTemplate
	logger               *slog.Logger
}

// Replace bufferedCloseWriter with simpleFileWriter
type simpleFileWriter struct {
	path string
}

func (w *simpleFileWriter) Write(p []byte) (n int, err error) {
	// Opening and closing the file is not efficient, but's makes handling log rotation easier
	// TODO: Either do what traefik does (listen to USR1 signal and rotate) or use a buffered writer with a timeout
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	return file.Write(p)
}

// Update createLogger to use simpleFileWriter
func createLogger(name, level, format, path string) *slog.Logger {
	var logLevel slog.Level
	level = strings.ToLower(level) // Convert level to lowercase
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
		if level != "" {
			log.Printf("[WARN] Unknown log level '%s', defaulting to 'info'", level)
		}
	}

	opts := &slog.HandlerOptions{Level: logLevel}

	var writer io.Writer
	switch strings.ToLower(path) {
	case "", "stderr":
		writer = os.Stderr
	case "stdout":
		writer = os.Stdout
	default:
		writer = &simpleFileWriter{path: path}
		log.Printf("[INFO] Using file %s for logging", path)
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(writer, opts)
		log.Printf("[INFO] Logger format set to JSON")
	} else {
		handler = slog.NewTextHandler(writer, opts)
		log.Printf("[INFO] Logger format set to text")
	}

	return slog.New(handler).With("plugin", name)
}

// New creates a new plugin instance.
func New(_ context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if next == nil {
		return nil, fmt.Errorf("%s: no next handler provided", name)
	}

	if cfg == nil {
		return nil, fmt.Errorf("%s: no config provided", name)
	}

	// Create logger first so we can use it for debugging
	logger := createLogger(name, cfg.LogLevel, cfg.LogFormat, cfg.LogPath)
	logger.Debug("initializing plugin",
		"logLevel", cfg.LogLevel,
		"logFormat", cfg.LogFormat,
		"logPath", cfg.LogPath)

	if !cfg.Enabled {
		logger.Info("plugin disabled")
		return &Plugin{
			next:    next,
			name:    name,
			db:      nil,
			enabled: false,
			logger:  logger,
		}, nil
	}

	if http.StatusText(cfg.DisallowedStatusCode) == "" {
		return nil, fmt.Errorf("%s: %d is not a valid http status code", name, cfg.DisallowedStatusCode)
	}

	if cfg.DatabaseFilePath == "" {
		return nil, fmt.Errorf("%s: no database file path configured", name)
	}

	db, err := ip2location.OpenDB(cfg.DatabaseFilePath)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to open database: %w", name, err)
	}

	// Check database version
	version, err := GetDatabaseVersion(cfg.DatabaseFilePath)
	if err != nil {
		logger.Warn("failed to read database version", "error", err)
	} else {
		logger.Info("database version", "version", version.String())
	}

	allowedIPBlocks, err := initIPBlocks(cfg.AllowedIPBlocks)
	if err != nil {
		return nil, fmt.Errorf("%s: failed loading allowed CIDR blocks: %w", name, err)
	}

	blockedIPBlocks, err := initIPBlocks(cfg.BlockedIPBlocks)
	if err != nil {
		return nil, fmt.Errorf("%s: failed loading allowed CIDR blocks: %w", name, err)
	}

	var banHtmlContent string
	if cfg.BanHtmlFilePath != "" {
		content, err := os.ReadFile(cfg.BanHtmlFilePath)
		if err != nil {
			log.Printf("%s: warning - could not load ban HTML file %s: %v", name, cfg.BanHtmlFilePath, err)
		} else {
			banHtmlContent = string(content)
		}
	}

	return &Plugin{
		next:                 next,
		name:                 name,
		db:                   db,
		enabled:              cfg.Enabled,
		allowedCountries:     cfg.AllowedCountries,
		blockedCountries:     cfg.BlockedCountries,
		defaultAllow:         cfg.DefaultAllow,
		allowPrivate:         cfg.AllowPrivate,
		disallowedStatusCode: cfg.DisallowedStatusCode,
		banHtmlFilePath:      cfg.BanHtmlFilePath,
		allowedIPBlocks:      allowedIPBlocks,
		blockedIPBlocks:      blockedIPBlocks,
		banHtmlContent:       banHtmlContent,
		logger:               logger,
	}, nil
}

// ServeHTTP implements the http.Handler interface.
func (p Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !p.enabled {
		p.logger.Info("plugin disabled, passing request through")
		p.next.ServeHTTP(rw, req)
		return
	}

	for _, ip := range p.GetRemoteIPs(req) {
		allowed, country, err := p.CheckAllowed(ip)
		if err != nil {
			p.logger.Error("request check failed",
				"ip", ip,
				"host", req.Host,
				"method", req.Method,
				"path", req.URL.Path,
				"error", err)
			p.serveBanHtml(rw, ip, "Unknown")
			return
		}
		if !allowed {
			p.logger.Info("blocked request",
				"ip", ip,
				"country", country,
				"host", req.Host,
				"method", req.Method,
				"path", req.URL.Path)
			p.serveBanHtml(rw, ip, country)
			return
		}
	}

	p.next.ServeHTTP(rw, req)
}

// GetRemoteIPs collects the remote IPs from the X-Forwarded-For and X-Real-IP headers.
func (p Plugin) GetRemoteIPs(req *http.Request) []string {
	uniqIPs := make(map[string]struct{})

	if xff := req.Header.Get("x-forwarded-for"); xff != "" {
		for _, ip := range strings.Split(xff, ",") {
			ip = cleanIPAddress(ip)
			if ip == "" {
				continue
			}
			uniqIPs[ip] = struct{}{}
		}
	}
	if xri := req.Header.Get("x-real-ip"); xri != "" {
		for _, ip := range strings.Split(xri, ",") {
			ip = cleanIPAddress(ip)
			if ip == "" {
				continue
			}
			uniqIPs[ip] = struct{}{}
		}
	}

	var ips []string
	for ip := range uniqIPs {
		ips = append(ips, ip)
	}

	return ips
}

func cleanIPAddress(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	// Split IP from port if port exists (e.g., "192.168.1.1:8080")
	host, _, err := net.SplitHostPort(ip)
	if err == nil {
		return host
	}
	return ip // If no port, return the original IP
}

// CheckAllowed checks whether a given IP address is allowed according to the configured allowed countries.
func (p Plugin) CheckAllowed(ip string) (allow bool, country string, err error) {
	var allowedCountry, allowedIP, blockedCountry, blockedIP bool
	var allowedNetworkLength, blockedNetworkLength int

	country, err = p.Lookup(ip)
	if err != nil {
		return false, ip, fmt.Errorf("lookup of %s failed: %w", ip, err)
	}

	if country == EmptyCountry {
		return p.allowPrivate, country, nil
	}

	if country != "-" {
		for _, item := range p.blockedCountries {
			if item == country {
				blockedCountry = true

				break
			}
		}

		for _, item := range p.allowedCountries {
			if item == country {
				allowedCountry = true
			}
		}
	}

	blocked, blockedNetworkLength, err := p.isBlockedIPBlocks(ip)
	if err != nil {
		return false, ip, fmt.Errorf("failed to check if IP %q is blocked by IP block: %w", ip, err)
	}

	if blocked {
		blockedIP = true
	}

	for _, allowedCountry := range p.allowedCountries {
		if allowedCountry == country {
			return true, ip, nil
		}
	}

	allowed, allowedNetBits, err := p.isAllowedIPBlocks(ip)
	if err != nil {
		return false, ip, fmt.Errorf("failed to check if IP %q is allowed by IP block: %w", ip, err)
	}

	if allowed {
		allowedIP = true
		allowedNetworkLength = allowedNetBits
	}

	// Handle final values
	//
	// NB: discrete IPs have higher priority than countries:  more specific to less specific.

	// NB: whichever matched prefix is longer has higher priority: more specific to less specific.
	if allowedNetworkLength < blockedNetworkLength {
		if blockedIP {
			return false, country, nil
		}

		if allowedIP {
			return true, country, nil
		}
	} else {
		if allowedIP {
			return true, country, nil
		}

		if blockedIP {
			return false, country, nil
		}
	}

	if allowedCountry {
		return true, country, nil
	}

	if blockedCountry {
		return false, country, nil
	}

	return p.defaultAllow, country, nil
}

// Lookup queries the ip2location database for a given IP address.
func (p Plugin) Lookup(ip string) (string, error) {
	record, err := p.db.Get_country_short(ip)
	if err != nil {
		return "", err
	}

	country := record.Country_short
	if strings.HasPrefix(strings.ToLower(country), "invalid") {
		return "", errors.New(country)
	}

	return record.Country_short, nil
}

// Create IP Networks using CIDR block array
func initIPBlocks(ipBlocks []string) ([]*net.IPNet, error) {

	var ipBlocksNet []*net.IPNet

	for _, cidr := range ipBlocks {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse error on %q: %v", cidr, err)
		}
		ipBlocksNet = append(ipBlocksNet, block)
	}

	return ipBlocksNet, nil
}

// isAllowedIPBlocks checks if an IP is allowed base on the allowed CIDR blocks
func (p Plugin) isAllowedIPBlocks(ip string) (bool, int, error) {
	return p.isInIPBlocks(ip, p.allowedIPBlocks)
}

// isBlockedIPBlocks checks if an IP is allowed base on the blocked CIDR blocks
func (p Plugin) isBlockedIPBlocks(ip string) (bool, int, error) {
	return p.isInIPBlocks(ip, p.blockedIPBlocks)
}

// isInIPBlocks indicates whether the given IP exists in any of the IP subnets contained within ipBlocks.
func (p Plugin) isInIPBlocks(ip string, ipBlocks []*net.IPNet) (bool, int, error) {
	ipAddress := net.ParseIP(ip)

	if ipAddress == nil {
		return false, 0, fmt.Errorf("unable parse IP address from address [%s]", ip)
	}

	for _, block := range ipBlocks {
		if block.Contains(ipAddress) {
			ones, _ := block.Mask.Size()

			return true, ones, nil
		}
	}

	return false, 0, nil
}

// Update the serveBanHtml function to use simple string replacement
func (p Plugin) serveBanHtml(rw http.ResponseWriter, ip, country string) {
	if p.banHtmlContent != "" {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.WriteHeader(p.disallowedStatusCode)

		if country == EmptyCountry || country == "" {
			country = "Unknown"
		}

		// Simple string replacements
		content := p.banHtmlContent
		content = strings.ReplaceAll(content, "{{.Country}}", country)
		content = strings.ReplaceAll(content, "{{.IP}}", ip)

		_, _ = rw.Write([]byte(content))
		return
	}
	rw.WriteHeader(p.disallowedStatusCode)
}
