package nutanix_exporter

import (
	"testing"
	"time"

	config_util "github.com/prometheus/common/config"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestConfig_UnmarshalYAML(t *testing.T) {
	strConfig := `
prism_central_url: "https://prism.example.com:9440"
prism_central_name: "prod-prism"
cluster_refresh_interval: 45m
cluster_prefix: "prod-"
pc_api_version: "v4"
config_path: "/etc/nutanix-configs"
pc_username: "admin"
pc_password: "secret"
pe_credentials:
  cluster1:
    username: "pe-admin1"
    password: "pe-secret1"
  cluster2:
    username: "pe-admin2"
    password: "pe-secret2"
`

	var c Config

	require.NoError(t, yaml.UnmarshalStrict([]byte(strConfig), &c))

	require.Equal(t, "https://prism.example.com:9440", c.PrismCentralURL.String())
	require.Equal(t, "prod-prism", c.PrismCentralName)
	require.Equal(t, 45*time.Minute, c.ClusterRefreshInterval)
	require.Equal(t, "prod-", c.ClusterPrefix)
	require.Equal(t, "v4", c.PCAPIVersion)
	require.Equal(t, "/etc/nutanix-configs", c.ConfigPath)
	require.Equal(t, config_util.Secret("admin"), c.PCUsername)
	require.Equal(t, config_util.Secret("secret"), c.PCPassword)
	require.Len(t, c.PECredentials, 2)
	require.Equal(t, PECredential{
		Username: config_util.Secret("pe-admin1"),
		Password: config_util.Secret("pe-secret1"),
	}, c.PECredentials["cluster1"])
	require.Equal(t, PECredential{
		Username: config_util.Secret("pe-admin2"),
		Password: config_util.Secret("pe-secret2"),
	}, c.PECredentials["cluster2"])
}

func TestConfig_UnmarshalYAML_WithDefaults(t *testing.T) {
	strConfig := `
prism_central_url: "https://prism.example.com:9440"
prism_central_name: "prod-prism"
pc_username: "admin"
pc_password: "secret"
`

	var c Config

	require.NoError(t, yaml.UnmarshalStrict([]byte(strConfig), &c))

	// Check defaults are applied
	require.Equal(t, 30*time.Minute, c.ClusterRefreshInterval)
	require.Equal(t, "v4", c.PCAPIVersion)
	require.Equal(t, "./configs", c.ConfigPath)
}

func TestConfig_InstanceKey(t *testing.T) {
	url, err := config_util.NewURL("https://prism.example.com:9440")
	require.NoError(t, err)

	c := Config{
		PrismCentralURL: *url,
	}

	ik, err := c.InstanceKey("agent-key")

	require.NoError(t, err)
	require.Equal(t, "https://prism.example.com:9440", ik)
}

func TestConfig_InstanceKey_MissingURL(t *testing.T) {
	c := Config{}

	_, err := c.InstanceKey("agent-key")

	require.Error(t, err)
	require.Contains(t, err.Error(), "prism_central_url is required")
}

func TestConfig_Name(t *testing.T) {
	c := Config{}
	require.Equal(t, "nutanix_exporter", c.Name())
}

func TestNormalizeClusterName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase letters",
			input:    "cluster",
			expected: "CLUSTER",
		},
		{
			name:     "mixed case",
			input:    "ClusterName",
			expected: "CLUSTERNAME",
		},
		{
			name:     "with dots",
			input:    "cluster.name",
			expected: "CLUSTER_NAME",
		},
		{
			name:     "with dashes",
			input:    "cluster-name",
			expected: "CLUSTER_NAME",
		},
		{
			name:     "with spaces",
			input:    "cluster name",
			expected: "CLUSTER_NAME",
		},
		{
			name:     "with numbers",
			input:    "cluster123",
			expected: "CLUSTER123",
		},
		{
			name:     "complex name",
			input:    "prod-cluster.name-01",
			expected: "PROD_CLUSTER_NAME_01",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeClusterName(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}
