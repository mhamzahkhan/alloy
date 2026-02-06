package nutanix

import (
	"fmt"
	"time"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/prometheus/exporter"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/static/integrations"
	"github.com/grafana/alloy/internal/static/integrations/nutanix_exporter"
	"github.com/grafana/alloy/syntax/alloytypes"
	config_util "github.com/prometheus/common/config"
)

func init() {
	component.Register(component.Registration{
		Name:      "prometheus.exporter.nutanix",
		Stability: featuregate.StabilityExperimental,
		Args:      Arguments{},
		Exports:   exporter.Exports{},

		Build: exporter.New(createExporter, "nutanix"),
	})
}

func createExporter(opts component.Options, args component.Arguments) (integrations.Integration, string, error) {
	a := args.(Arguments)
	defaultInstanceKey := opts.ID
	return integrations.NewIntegrationWithInstanceKey(opts.Logger, a.Convert(), defaultInstanceKey)
}

// DefaultArguments holds the default settings for the nutanix exporter.
var DefaultArguments = Arguments{
	ClusterRefreshInterval: 30 * time.Minute,
	PCAPIVersion:           "v4",
	ConfigPath:             "./configs",
}

// Arguments configures the prometheus.exporter.nutanix component.
type Arguments struct {
	// PrismCentralURL is the URL of the Prism Central instance.
	PrismCentralURL string `alloy:"prism_central_url,attr"`

	// PrismCentralName is the name of the Prism Central instance.
	PrismCentralName string `alloy:"prism_central_name,attr"`

	// ClusterRefreshInterval is the interval at which to refresh the cluster list.
	ClusterRefreshInterval time.Duration `alloy:"cluster_refresh_interval,attr,optional"`

	// ClusterPrefix filters clusters by name prefix.
	ClusterPrefix string `alloy:"cluster_prefix,attr,optional"`

	// PCAPIVersion is the Prism Central API version to use (v3, v4b1, or v4).
	PCAPIVersion string `alloy:"pc_api_version,attr,optional"`

	// ConfigPath is the path to the directory containing metric configuration YAML files.
	ConfigPath string `alloy:"config_path,attr,optional"`

	// Credentials for Prism Central.
	PrismCentral *PrismCentralCredentials `alloy:"prism_central_credentials,block"`

	// Credentials for Prism Element clusters.
	PrismElement []PrismElementCredentials `alloy:"prism_element_credentials,block,optional"`
}

// PrismCentralCredentials contains Prism Central authentication credentials.
type PrismCentralCredentials struct {
	// Username for Prism Central authentication.
	Username alloytypes.Secret `alloy:"username,attr"`

	// Password for Prism Central authentication.
	Password alloytypes.Secret `alloy:"password,attr"`
}

// PrismElementCredentials contains Prism Element cluster-specific credentials.
type PrismElementCredentials struct {
	// ClusterName is the name of the Prism Element cluster.
	ClusterName string `alloy:"cluster_name,attr"`

	// Username for Prism Element authentication.
	Username alloytypes.Secret `alloy:"username,attr"`

	// Password for Prism Element authentication.
	Password alloytypes.Secret `alloy:"password,attr"`
}

// Convert converts Arguments to the integration config.
func (a *Arguments) Convert() *nutanix_exporter.Config {
	cfg := &nutanix_exporter.Config{
		PrismCentralName:       a.PrismCentralName,
		ClusterRefreshInterval: a.ClusterRefreshInterval,
		ClusterPrefix:          a.ClusterPrefix,
		PCAPIVersion:           a.PCAPIVersion,
		ConfigPath:             a.ConfigPath,
	}

	// Parse the URL
	if a.PrismCentralURL != "" {
		if url, err := config_util.NewURL(a.PrismCentralURL); err == nil {
			cfg.PrismCentralURL = *url
		}
	}

	// Configure Prism Central credentials
	if a.PrismCentral != nil {
		cfg.PCUsername = config_util.Secret(a.PrismCentral.Username)
		cfg.PCPassword = config_util.Secret(a.PrismCentral.Password)
	}

	// Configure Prism Element credentials if specified
	if len(a.PrismElement) > 0 {
		cfg.PECredentials = make(map[string]nutanix_exporter.PECredential)
		for _, pe := range a.PrismElement {
			cfg.PECredentials[pe.ClusterName] = nutanix_exporter.PECredential{
				Username: config_util.Secret(pe.Username),
				Password: config_util.Secret(pe.Password),
			}
		}
	}

	return cfg
}

// SetToDefault implements syntax.Defaulter.
func (a *Arguments) SetToDefault() {
	*a = DefaultArguments
}

// Validate checks if the Arguments are valid.
func (a *Arguments) Validate() error {
	// Validate required fields
	if a.PrismCentralURL == "" {
		return fmt.Errorf("prism_central_url is required")
	}
	if a.PrismCentralName == "" {
		return fmt.Errorf("prism_central_name is required")
	}

	// Validate that Prism Central credentials are configured
	if a.PrismCentral == nil {
		return fmt.Errorf("prism_central_credentials block is required")
	}
	if a.PrismCentral.Username == "" {
		return fmt.Errorf("prism_central_credentials.username is required")
	}
	if a.PrismCentral.Password == "" {
		return fmt.Errorf("prism_central_credentials.password is required")
	}

	// Validate PC API version
	if a.PCAPIVersion != "" && a.PCAPIVersion != "v3" && a.PCAPIVersion != "v4b1" && a.PCAPIVersion != "v4" {
		return fmt.Errorf("pc_api_version must be one of: v3, v4b1, v4")
	}

	return nil
}
