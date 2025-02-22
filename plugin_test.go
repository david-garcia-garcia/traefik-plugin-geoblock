package traefik_plugin_geoblock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	pluginName = "geoblock"
	dbFilePath = "./IP2LOCATION-LITE-DB1.IPV6.BIN"
)

type noopHandler struct{}

func (n noopHandler) ServeHTTP(rw http.ResponseWriter, _ *http.Request) {
	rw.WriteHeader(http.StatusTeapot)
}

func TestNew(t *testing.T) {
	t.Run("Disabled", func(t *testing.T) {
		plugin, err := New(context.TODO(), &noopHandler{}, &Config{Enabled: false}, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/foobar", nil)

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusTeapot {
			t.Errorf("expected status code %d, but got: %d", http.StatusTeapot, rr.Code)
		}
	})

	t.Run("NoNextHandler", func(t *testing.T) {
		plugin, err := New(context.TODO(), nil, &Config{Enabled: true}, pluginName)
		if err == nil {
			t.Errorf("expected error, but got none")
		}
		if plugin != nil {
			t.Error("expected plugin to be nil, but is not")
		}
	})

	t.Run("Nogeoblock.Config", func(t *testing.T) {
		plugin, err := New(context.TODO(), &noopHandler{}, nil, pluginName)
		if err == nil {
			t.Errorf("expected error, but got none")
		}
		if plugin != nil {
			t.Error("expected plugin to be nil, but is not")
		}
	})

	t.Run("InvalidDisallowedStatusCode", func(t *testing.T) {
		plugin, err := New(context.TODO(), &noopHandler{}, &Config{Enabled: true, DisallowedStatusCode: -1}, pluginName)
		if err == nil {
			t.Errorf("expected error, but got none")
		}
		if plugin != nil {
			t.Error("expected plugin to be nil, but is not")
		}
	})

	t.Run("UnableToFindDatabase", func(t *testing.T) {
		plugin, err := New(context.TODO(), &noopHandler{}, &Config{Enabled: true, DisallowedStatusCode: http.StatusForbidden, DatabaseFilePath: "bad-database"}, pluginName)
		if err == nil {
			t.Errorf("expected error, but got none")
		}
		if plugin != nil {
			t.Error("expected plugin to be nil, but is not")
		}
	})

	t.Run("InvalidDatabaseVersion", func(t *testing.T) {
		plugin, err := New(context.TODO(), &noopHandler{}, &Config{
			Enabled:          true,
			DatabaseFilePath: "./testdata/invalid.bin",
		}, pluginName)
		if err == nil {
			t.Errorf("expected error about invalid database version, but got none")
		}
		if plugin != nil {
			t.Error("expected plugin to be nil, but is not")
		}
	})
}

func TestPlugin_ServeHTTP(t *testing.T) {
	t.Run("Allowed", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			AllowedCountries:     []string{"AU"},
			DisallowedStatusCode: http.StatusOK,
		}

		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/foobar", nil)
		req.Header.Set("X-Real-IP", "1.1.1.1")

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusTeapot {
			t.Errorf("expected status code %d, but got: %d", http.StatusTeapot, rr.Code)
		}
	})

	t.Run("AllowedPrivate", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			AllowedCountries:     []string{},
			AllowPrivate:         true,
			DisallowedStatusCode: http.StatusOK,
		}

		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/foobar", nil)
		req.Header.Set("X-Real-IP", "192.168.178.66")

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusTeapot {
			t.Errorf("expected status code %d, but got: %d", http.StatusTeapot, rr.Code)
		}
	})

	t.Run("AllowedPrivate172Range", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			AllowedCountries:     []string{},
			AllowPrivate:         true,
			DisallowedStatusCode: http.StatusOK,
		}

		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/foobar", nil)
		req.Header.Set("X-Real-IP", "172.19.0.1")

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusTeapot {
			t.Errorf("expected status code %d, but got: %d", http.StatusTeapot, rr.Code)
		}
	})

	t.Run("Disallowed", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			AllowedCountries:     []string{"DE"},
			DisallowedStatusCode: http.StatusForbidden,
		}

		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/foobar", nil)
		req.Header.Set("X-Real-IP", "1.1.1.1")

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status code %d, but got: %d", http.StatusForbidden, rr.Code)
		}

		// Check that response contains the IP address
		body := rr.Body.String()
		if !strings.Contains(body, "1.1.1.1") {
			t.Errorf("expected response to contain IP address '1.1.1.1', but got: %s", body)
		}
	})

	t.Run("DisallowedPrivate", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			AllowedCountries:     []string{},
			AllowPrivate:         false,
			DisallowedStatusCode: http.StatusForbidden,
		}

		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/foobar", nil)
		req.Header.Set("X-Real-IP", "192.168.178.66")

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("expected status code %d, but got: %d", http.StatusForbidden, rr.Code)
		}

		// Check that response contains the IP address
		body := rr.Body.String()
		if !strings.Contains(body, "192.168.178.66") {
			t.Errorf("expected response to contain IP address '192.168.178.66', but got: %s", body)
		}
	})

	t.Run("Blocklist", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			BlockedCountries:     []string{"US"},
			AllowPrivate:         false,
			DefaultAllow:         true,
			DisallowedStatusCode: http.StatusForbidden,
		}

		testRequest(t, "US IP blocked", cfg, "8.8.8.8", http.StatusForbidden)
		testRequest(t, "DE IP allowed", cfg, "185.5.82.105", 0)

		cfg.BlockedCountries = nil
		cfg.BlockedIPBlocks = []string{"8.8.8.0/24"}

		testRequest(t, "Google DNS-A blocked", cfg, "8.8.8.8", http.StatusForbidden)
		testRequest(t, "Google DNS-B allowed", cfg, "8.8.4.4", 0)

		cfg.AllowedIPBlocks = []string{"8.8.8.7/32"}

		testRequest(t, "Higher specificity IP CIDR allow trumps lower specificity IP CIDR block", cfg, "8.8.8.7", 0)
		testRequest(t, "Higher specificity IP CIDR allow should not override encompassing CIDR block", cfg, "8.8.8.9", http.StatusForbidden)

		cfg.DefaultAllow = false

		testRequest(t, "Default allow false", cfg, "8.8.4.4", http.StatusForbidden)
	})
}

func testRequest(t *testing.T, testName string, cfg *Config, ip string, expectedStatus int) {
	t.Run(testName, func(t *testing.T) {
		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/foobar", nil)
		req.Header.Set("X-Real-IP", ip)

		rr := httptest.NewRecorder()
		plugin.ServeHTTP(rr, req)

		if expectedStatus > 0 && rr.Code != expectedStatus {
			t.Errorf("expected status code %d, but got: %d", expectedStatus, rr.Code)
		}
	})
}

func TestPlugin_Lookup(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			AllowedCountries:     []string{},
			AllowPrivate:         false,
			DisallowedStatusCode: http.StatusForbidden,
		}

		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		country, err := plugin.(*Plugin).Lookup("8.8.8.8")
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}
		if country != "US" {
			t.Errorf("expected country to be %s, but got: %s", "US", country)
		}
	})

	t.Run("Invalid", func(t *testing.T) {
		cfg := &Config{
			Enabled:              true,
			DatabaseFilePath:     dbFilePath,
			AllowedCountries:     []string{},
			AllowPrivate:         false,
			DisallowedStatusCode: http.StatusForbidden,
		}

		plugin, err := New(context.TODO(), &noopHandler{}, cfg, pluginName)
		if err != nil {
			t.Errorf("expected no error, but got: %v", err)
		}

		country, err := plugin.(*Plugin).Lookup("foobar")
		if err == nil {
			t.Errorf("expected error, but got none")
		}
		if err.Error() != "Invalid IP address." {
			t.Errorf("unexpected error: %v", err)
		}
		if country != "" {
			t.Errorf("expected country to be empty, but was: %s", country)
		}
	})
}

func TestPlugin_ServeHTTP_MalformedIP(t *testing.T) {
	tests := []struct {
		name       string
		banIfError bool
		ip         string
		wantStatus int
	}{
		{
			name:       "malformed IP with banIfError true",
			banIfError: true,
			ip:         "not.an.ip.address",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "malformed IP with banIfError false",
			banIfError: false,
			ip:         "not.an.ip.address",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test response recorder
			rr := httptest.NewRecorder()

			// Create a test request with the malformed IP
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", tt.ip)

			// Create a mock next handler that always returns 200 OK
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Create plugin config
			cfg := &Config{
				Enabled:              true,
				DisallowedStatusCode: http.StatusForbidden,
				BanIfError:           tt.banIfError,
			}

			// Initialize plugin
			plugin, err := New(context.Background(), next, cfg, "test")
			if err != nil {
				t.Fatalf("Failed to create plugin: %v", err)
			}

			// Serve the request
			plugin.ServeHTTP(rr, req)

			// Check the status code
			if rr.Code != tt.wantStatus {
				t.Errorf("ServeHTTP() status = %v, want %v", rr.Code, tt.wantStatus)
			}
		})
	}
}
