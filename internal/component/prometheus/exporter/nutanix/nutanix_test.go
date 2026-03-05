package nutanix

import (
	"testing"
	"time"

	"github.com/grafana/alloy/internal/static/integrations/nutanix_exporter"
	"github.com/grafana/alloy/syntax"
	"github.com/grafana/alloy/syntax/alloytypes"
	config_util "github.com/prometheus/common/config"
	"github.com/stretchr/testify/require"
)

func TestAlloyUnmarshal(t *testing.T) {
	alloyConfig := `
	prism_central_url        = "https://prism.example.com:9440"
	prism_central_name       = "prod-prism"
	cluster_refresh_interval = "45m"
	cluster_prefix           = "prod-"
	pc_api_version           = "v4"
	config_path              = "/etc/nutanix-configs"

	prism_central_credentials {
		username = "admin"
		password = "secret"
	}

	prism_element_credentials {
		cluster_name = "cluster1"
		username     = "pe-admin1"
		password     = "pe-secret1"
	}

	prism_element_credentials {
		cluster_name = "cluster2"
		username     = "pe-admin2"
		password     = "pe-secret2"
	}
	`

	var args Arguments
	err := syntax.Unmarshal([]byte(alloyConfig), &args)
	require.NoError(t, err)

	require.Equal(t, "https://prism.example.com:9440", args.PrismCentralURL)
	require.Equal(t, "prod-prism", args.PrismCentralName)
	require.Equal(t, 45*time.Minute, args.ClusterRefreshInterval)
	require.Equal(t, "prod-", args.ClusterPrefix)
	require.Equal(t, "v4", args.PCAPIVersion)
	require.Equal(t, "/etc/nutanix-configs", args.ConfigPath)

	require.NotNil(t, args.PrismCentral)
	require.Equal(t, alloytypes.Secret("admin"), args.PrismCentral.Username)
	require.Equal(t, alloytypes.Secret("secret"), args.PrismCentral.Password)

	require.Len(t, args.PrismElement, 2)
	require.Equal(t, "cluster1", args.PrismElement[0].ClusterName)
	require.Equal(t, alloytypes.Secret("pe-admin1"), args.PrismElement[0].Username)
	require.Equal(t, alloytypes.Secret("pe-secret1"), args.PrismElement[0].Password)
	require.Equal(t, "cluster2", args.PrismElement[1].ClusterName)
	require.Equal(t, alloytypes.Secret("pe-admin2"), args.PrismElement[1].Username)
	require.Equal(t, alloytypes.Secret("pe-secret2"), args.PrismElement[1].Password)
}

func TestConvert(t *testing.T) {
	args := Arguments{
		PrismCentralURL:        "https://prism.example.com:9440",
		PrismCentralName:       "prod-prism",
		ClusterRefreshInterval: 45 * time.Minute,
		ClusterPrefix:          "prod-",
		PCAPIVersion:           "v4",
		ConfigPath:             "/etc/configs",
		PrismCentral: &PrismCentralCredentials{
			Username: "admin",
			Password: "secret",
		},
		PrismElement: []PrismElementCredentials{
			{
				ClusterName: "cluster1",
				Username:    "pe-admin1",
				Password:    "pe-secret1",
			},
			{
				ClusterName: "cluster2",
				Username:    "pe-admin2",
				Password:    "pe-secret2",
			},
		},
	}

	cfg := args.Convert()

	require.Equal(t, "prod-prism", cfg.PrismCentralName)
	require.Equal(t, 45*time.Minute, cfg.ClusterRefreshInterval)
	require.Equal(t, "prod-", cfg.ClusterPrefix)
	require.Equal(t, "v4", cfg.PCAPIVersion)
	require.Equal(t, "/etc/configs", cfg.ConfigPath)
	require.Equal(t, config_util.Secret("admin"), cfg.PCUsername)
	require.Equal(t, config_util.Secret("secret"), cfg.PCPassword)
	require.Len(t, cfg.PECredentials, 2)
	require.Equal(t, nutanix_exporter.PECredential{
		Username: config_util.Secret("pe-admin1"),
		Password: config_util.Secret("pe-secret1"),
	}, cfg.PECredentials["cluster1"])
	require.Equal(t, nutanix_exporter.PECredential{
		Username: config_util.Secret("pe-admin2"),
		Password: config_util.Secret("pe-secret2"),
	}, cfg.PECredentials["cluster2"])
}

func TestSetToDefault(t *testing.T) {
	var args Arguments
	args.SetToDefault()

	require.Equal(t, 30*time.Minute, args.ClusterRefreshInterval)
	require.Equal(t, "v4", args.PCAPIVersion)
	require.Equal(t, "./configs", args.ConfigPath)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		args    Arguments
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration",
			args: Arguments{
				PrismCentralURL:  "https://prism.example.com:9440",
				PrismCentralName: "prod-prism",
				PrismCentral: &PrismCentralCredentials{
					Username: "admin",
					Password: "secret",
				},
			},
			wantErr: false,
		},
		{
			name: "missing prism_central_url",
			args: Arguments{
				PrismCentralName: "prod-prism",
				PrismCentral: &PrismCentralCredentials{
					Username: "admin",
					Password: "secret",
				},
			},
			wantErr: true,
			errMsg:  "prism_central_url is required",
		},
		{
			name: "missing prism_central_name",
			args: Arguments{
				PrismCentralURL: "https://prism.example.com:9440",
				PrismCentral: &PrismCentralCredentials{
					Username: "admin",
					Password: "secret",
				},
			},
			wantErr: true,
			errMsg:  "prism_central_name is required",
		},
		{
			name: "missing credentials block",
			args: Arguments{
				PrismCentralURL:  "https://prism.example.com:9440",
				PrismCentralName: "prod-prism",
			},
			wantErr: true,
			errMsg:  "prism_central_credentials block is required",
		},
		{
			name: "missing username",
			args: Arguments{
				PrismCentralURL:  "https://prism.example.com:9440",
				PrismCentralName: "prod-prism",
				PrismCentral: &PrismCentralCredentials{
					Password: "secret",
				},
			},
			wantErr: true,
			errMsg:  "prism_central_credentials.username is required",
		},
		{
			name: "missing password",
			args: Arguments{
				PrismCentralURL:  "https://prism.example.com:9440",
				PrismCentralName: "prod-prism",
				PrismCentral: &PrismCentralCredentials{
					Username: "admin",
				},
			},
			wantErr: true,
			errMsg:  "prism_central_credentials.password is required",
		},
		{
			name: "invalid pc_api_version",
			args: Arguments{
				PrismCentralURL:  "https://prism.example.com:9440",
				PrismCentralName: "prod-prism",
				PCAPIVersion:     "v5",
				PrismCentral: &PrismCentralCredentials{
					Username: "admin",
					Password: "secret",
				},
			},
			wantErr: true,
			errMsg:  "pc_api_version must be one of: v3, v4b1, v4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.args.Validate()
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
