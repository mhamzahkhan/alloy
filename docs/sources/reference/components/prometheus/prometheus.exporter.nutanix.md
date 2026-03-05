---
canonical: https://grafana.com/docs/alloy/latest/reference/components/prometheus/prometheus.exporter.nutanix/
aliases:
  - ../prometheus.exporter.nutanix/ # /docs/alloy/latest/reference/components/prometheus.exporter.nutanix/
description: Learn about prometheus.exporter.nutanix
labels:
  stage: experimental
  products:
    - oss
title: prometheus.exporter.nutanix
---

# `prometheus.exporter.nutanix`

The `prometheus.exporter.nutanix` component embeds the [`nutanix-exporter`](https://github.com/ingka-group/nutanix-exporter) for collecting metrics from Nutanix Prism Central and Prism Element clusters.

The exporter automatically discovers all Prism Element clusters from a Prism Central instance and exposes metrics from multiple APIv2 endpoints, including VMs, Hosts, Clusters, and Storage Containers.

## Usage

```alloy
prometheus.exporter.nutanix "example" {
    prism_central_url  = "https://prism.example.com:9440"
    prism_central_name = "production-prism"

    prism_central_credentials {
        username = env("PC_USERNAME")
        password = env("PC_PASSWORD")
    }

    prism_element_credentials {
        cluster_name = "cluster-01"
        username     = env("PE_USERNAME_CLUSTER_01")
        password     = env("PE_PASSWORD_CLUSTER_01")
    }

    prism_element_credentials {
        cluster_name = "cluster-02"
        username     = env("PE_USERNAME_CLUSTER_02")
        password     = env("PE_PASSWORD_CLUSTER_02")
    }
}
```

## Arguments

You can use the following arguments with `prometheus.exporter.nutanix`:

| Name                       | Type       | Description                                                                | Default      | Required |
|----------------------------|------------|----------------------------------------------------------------------------|--------------|----------|
| `prism_central_url`        | `string`   | The URL of the Prism Central instance.                                     |              | yes      |
| `prism_central_name`       | `string`   | The name of the Prism Central instance.                                    |              | yes      |
| `cluster_refresh_interval` | `duration` | The interval at which to refresh the cluster list.                         | `"30m"`      | no       |
| `cluster_prefix`           | `string`   | Filters clusters by name prefix.                                           |              | no       |
| `pc_api_version`           | `string`   | The Prism Central API version to use (`v3`, `v4b1`, or `v4`).             | `"v4"`       | no       |
| `config_path`              | `string`   | The path to the directory containing metric configuration YAML files.      | `"./configs"`| no       |

The `prism_central_credentials` block is required to provide authentication.

## Blocks

The following blocks are supported inside the definition of `prometheus.exporter.nutanix`:

| Hierarchy                      | Block                          | Description                                                   | Required |
|--------------------------------|--------------------------------|---------------------------------------------------------------|----------|
| prism_central_credentials      | [prism_central_credentials][]  | Configures Prism Central credentials.                         | yes      |
| prism_element_credentials      | [prism_element_credentials][]  | Configures Prism Element cluster credentials.                 | no       |

The `>` symbol indicates deeper levels of nesting.

[prism_central_credentials]: #prism_central_credentials-block
[prism_element_credentials]: #prism_element_credentials-block

### prism_central_credentials block

The `prism_central_credentials` block configures Prism Central authentication credentials.
You can specify only one `prism_central_credentials` block.

The following arguments are supported:

| Name       | Type     | Description                                    | Default | Required |
|------------|----------|------------------------------------------------|---------|----------|
| `username` | `secret` | The username for Prism Central authentication. |         | yes      |
| `password` | `secret` | The password for Prism Central authentication. |         | yes      |

### prism_element_credentials block

The `prism_element_credentials` block configures Prism Element cluster-specific credentials.
You can specify multiple `prism_element_credentials` blocks for different clusters.

The following arguments are supported:

| Name           | Type     | Description                                    | Default | Required |
|----------------|----------|------------------------------------------------|---------|----------|
| `cluster_name` | `string` | The name of the Prism Element cluster.         |         | yes      |
| `username`     | `secret` | The username for Prism Element authentication. |         | yes      |
| `password`     | `secret` | The password for Prism Element authentication. |         | yes      |

When Prism Element credentials aren't provided for a specific cluster, the exporter falls back to environment variables.
Environment variables use normalized cluster names with the format `PE_USERNAME_<CLUSTERNAME>` and `PE_PASSWORD_<CLUSTERNAME>`.
Cluster names are normalized by converting to uppercase and replacing non-alphanumeric characters with underscores.

For example, if your cluster is named `cluster.name-01`, use these environment variables:
- `PE_USERNAME_CLUSTER_NAME_01`
- `PE_PASSWORD_CLUSTER_NAME_01`

## Exported fields

{{< docs/shared lookup="reference/components/exporter-component-exports.md" source="alloy" version="<ALLOY_VERSION>" >}}

## Component health

`prometheus.exporter.nutanix` is only reported as unhealthy if given an invalid configuration or if the exporter service fails to start.
In those cases, exported fields retain their last healthy values.

## Debug information

`prometheus.exporter.nutanix` doesn't expose any component-specific debug information.

## Debug metrics

`prometheus.exporter.nutanix` doesn't expose any component-specific debug metrics.

## Metrics Configuration

Metrics are collected from the Prism Element v2.0 APIs.
The exporter supports the following endpoints:

- Clusters
- Hosts
- VMs
- Storage Containers

Additionally, the v1 VM API is supported for gathering additional stats not available in the v2 API.

The `config_path` directory contains YAML configuration files for each exporter.
Each entry must have the following fields:

- `name`: The name of the metric key in the API response
- `help`: User-defined description of the metric

Example metric configuration:

```yaml
- name: memory_mb
  help: Memory in MB.
- name: power_state
  help: Power state of the VM.
- name: vcpu_reservation_hz
  help: vCPU reservation in Hz.
- name: stats_num_iops
  help: Number of IOPS.
```

Nested fields in the API response are flattened and exposed like "parent_child", for example "stats_num_iops".

## Example

The following example uses a [`prometheus.scrape`][scrape] component to collect metrics from `prometheus.exporter.nutanix`:

```alloy
prometheus.exporter.nutanix "production" {
  prism_central_url        = "https://prism.example.com:9440"
  prism_central_name       = "production-prism"
  cluster_refresh_interval = "45m"
  cluster_prefix           = "prod-"
  pc_api_version           = "v4"

  prism_central_credentials {
    username = env("PC_USERNAME")
    password = env("PC_PASSWORD")
  }

  prism_element_credentials {
    cluster_name = "prod-cluster-01"
    username     = env("PE_USERNAME_01")
    password     = env("PE_PASSWORD_01")
  }

  prism_element_credentials {
    cluster_name = "prod-cluster-02"
    username     = env("PE_USERNAME_02")
    password     = env("PE_PASSWORD_02")
  }
}

// Configure a prometheus.scrape component to collect nutanix metrics.
prometheus.scrape "demo" {
  targets    = prometheus.exporter.nutanix.production.targets
  forward_to = [prometheus.remote_write.demo.receiver]
}

prometheus.remote_write "demo" {
  endpoint {
    url = PROMETHEUS_REMOTE_WRITE_URL

    basic_auth {
      username = USERNAME
      password = PASSWORD
    }
  }
}
```

Replace the following:

- _`PROMETHEUS_REMOTE_WRITE_URL`_: The URL of the Prometheus `remote_write` compatible server to send metrics to.
- _`USERNAME`_: The username to use for authentication to the `remote_write` API.
- _`PASSWORD`_: The password to use for authentication to the `remote_write` API.

[scrape]: ../prometheus.scrape/

<!-- START GENERATED COMPATIBLE COMPONENTS -->

## Compatible components

`prometheus.exporter.nutanix` has exports that can be consumed by the following components:

- Components that consume [Targets](../../../compatibility/#targets-consumers)

{{< admonition type="note" >}}
Connecting some components may not be sensible or components may require further configuration to make the connection work correctly.
Refer to the linked documentation for more details.
{{< /admonition >}}

<!-- END GENERATED COMPATIBLE COMPONENTS -->
