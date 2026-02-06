package nutanix_exporter

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	config_util "github.com/prometheus/common/config"

	"github.com/grafana/alloy/internal/static/integrations"
	integrations_v2 "github.com/grafana/alloy/internal/static/integrations/v2"
	"github.com/grafana/alloy/internal/static/integrations/v2/metricsutils"

	"github.com/ingka-group/nutanix-exporter/pkg/exporter"
)

// DefaultConfig provides default configuration values for the Nutanix exporter.
var DefaultConfig = Config{
	ClusterRefreshInterval: 30 * time.Minute,
	PCAPIVersion:           "v4",
	ConfigPath:             "./configs",
}

// Config controls the nutanix_exporter integration.
type Config struct {
	// PrismCentralURL is the URL of the Prism Central instance.
	PrismCentralURL config_util.URL `yaml:"prism_central_url"`

	// PrismCentralName is the name of the Prism Central instance.
	PrismCentralName string `yaml:"prism_central_name"`

	// ClusterRefreshInterval is the interval at which to refresh the cluster list.
	ClusterRefreshInterval time.Duration `yaml:"cluster_refresh_interval,omitempty"`

	// ClusterPrefix filters clusters by name prefix.
	ClusterPrefix string `yaml:"cluster_prefix,omitempty"`

	// PCAPIVersion is the Prism Central API version to use (v3, v4b1, or v4).
	PCAPIVersion string `yaml:"pc_api_version,omitempty"`

	// ConfigPath is the path to the directory containing metric configuration YAML files.
	ConfigPath string `yaml:"config_path,omitempty"`

	// Credentials for Prism Central.
	PCUsername config_util.Secret `yaml:"pc_username,omitempty"`
	PCPassword config_util.Secret `yaml:"pc_password,omitempty"`

	// Credentials for Prism Element clusters.
	// Map of cluster name to credentials.
	PECredentials map[string]PECredential `yaml:"pe_credentials,omitempty"`
}

// PECredential represents credentials for a Prism Element cluster.
type PECredential struct {
	Username config_util.Secret `yaml:"username"`
	Password config_util.Secret `yaml:"password"`
}

// UnmarshalYAML implements yaml.Unmarshaler for Config.
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultConfig
	type plain Config
	return unmarshal((*plain)(c))
}

// Name returns the name of the integration.
func (c *Config) Name() string {
	return "nutanix_exporter"
}

// InstanceKey returns the Prism Central URL as the instance identifier.
func (c *Config) InstanceKey(_ string) (string, error) {
	if c.PrismCentralURL.URL == nil {
		return "", fmt.Errorf("prism_central_url is required")
	}
	return c.PrismCentralURL.String(), nil
}

// NewIntegration creates a new nutanix_exporter integration.
func (c *Config) NewIntegration(logger log.Logger) (integrations.Integration, error) {
	return New(logger, c)
}

func init() {
	integrations.RegisterIntegration(&Config{})
	integrations_v2.RegisterLegacy(&Config{}, integrations_v2.TypeMultiplex, metricsutils.NewNamedShim("nutanix"))
}

// Integration wraps the Nutanix ExporterService.
type Integration struct {
	logger  log.Logger
	config  *Config
	service *exporter.ExporterService
}

// New creates a new nutanix_exporter integration.
func New(logger log.Logger, c *Config) (integrations.Integration, error) {
	if c.PrismCentralURL.URL == nil {
		return nil, fmt.Errorf("prism_central_url is required")
	}
	if c.PrismCentralName == "" {
		return nil, fmt.Errorf("prism_central_name is required")
	}

	// Create credential provider using configuration.
	level.Info(logger).Log("msg", "using configuration-based credential management")
	credProvider := newConfigCredentialProvider(c)

	// Convert Alloy config to nutanix-exporter config.
	nutanixCfg := &exporter.Config{
		PrismCentralURL:        c.PrismCentralURL.String(),
		PrismCentralName:       c.PrismCentralName,
		ClusterRefreshInterval: c.ClusterRefreshInterval,
		ClusterPrefix:          c.ClusterPrefix,
		PCAPIVersion:           c.PCAPIVersion,
		ConfigPath:             c.ConfigPath,
	}

	// Create the exporter service.
	exporterService := exporter.NewExporterService(nutanixCfg, credProvider)

	// Initialize the service without starting the HTTP server.
	if err := exporterService.StartWithServer(false); err != nil {
		return nil, fmt.Errorf("failed to start nutanix exporter service: %w", err)
	}

	return &Integration{
		logger:  logger,
		config:  c,
		service: exporterService,
	}, nil
}

// MetricsHandler returns the HTTP handler for the integration.
func (i *Integration) MetricsHandler() (http.Handler, error) {
	return i.service.GetHandler(), nil
}

// ScrapeConfigs returns the scrape configs for the integration.
func (i *Integration) ScrapeConfigs() []integrations.ScrapeConfig {
	// The Nutanix exporter uses dynamic targets based on discovered clusters.
	// Return an empty scrape config as metrics are served via the handler.
	return []integrations.ScrapeConfig{}
}

// Run runs the integration.
func (i *Integration) Run(ctx context.Context) error {
	// The service is already running from StartWithServer.
	// Just wait for context cancellation.
	<-ctx.Done()
	return i.service.Stop()
}

// configCredentialProvider implements CredentialProvider using config values.
type configCredentialProvider struct {
	config *Config
}

func newConfigCredentialProvider(cfg *Config) exporter.CredentialProvider {
	return &configCredentialProvider{config: cfg}
}

// GetPCCreds returns Prism Central credentials.
func (p *configCredentialProvider) GetPCCreds(cluster string) (string, string, error) {
	// Try config first.
	if p.config.PCUsername != "" && p.config.PCPassword != "" {
		return string(p.config.PCUsername), string(p.config.PCPassword), nil
	}

	// Fall back to environment variables.
	username := os.Getenv("PC_USERNAME")
	password := os.Getenv("PC_PASSWORD")
	if username == "" || password == "" {
		return "", "", fmt.Errorf("PC credentials not configured")
	}
	return username, password, nil
}

// GetPECreds returns Prism Element credentials for a specific cluster.
func (p *configCredentialProvider) GetPECreds(cluster string) (string, string, error) {
	// Try config first.
	if creds, ok := p.config.PECredentials[cluster]; ok {
		return string(creds.Username), string(creds.Password), nil
	}

	// Fall back to environment variables.
	// Environment variables use normalized cluster names (uppercase, non-alphanumeric -> underscore).
	normalizedName := normalizeClusterName(cluster)
	username := os.Getenv("PE_USERNAME_" + normalizedName)
	password := os.Getenv("PE_PASSWORD_" + normalizedName)
	if username == "" || password == "" {
		return "", "", fmt.Errorf("PE credentials not configured for cluster %s", cluster)
	}
	return username, password, nil
}

// Refresh is a no-op for config-based credentials.
func (p *configCredentialProvider) Refresh() error {
	return nil
}

// normalizeClusterName converts a cluster name to the format used in environment variables.
// Converts to uppercase and replaces non-alphanumeric characters with underscores.
func normalizeClusterName(name string) string {
	var result strings.Builder
	result.Grow(len(name))

	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			result.WriteRune(ch)
		} else {
			result.WriteRune('_')
		}
	}

	return strings.ToUpper(result.String())
}
