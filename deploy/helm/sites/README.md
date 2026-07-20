# Per-site Helm values

Site-specific values files for the Helm charts under `deploy/helm/`, one
directory per site.

```
deploy/helm/
├── sbc/                         # the SBC chart (templates + default values.yaml)
├── central-config/              # the central-config chart
└── sites/
    ├── sbc/
    │   └── <site-id>/values.yaml            # per-site overrides for the sbc chart
    └── central-config/
        └── <site-id>/values.yaml            # per-site overrides for central-config
```

- **Charts** live in `deploy/helm/<chart>/`. Their `values.yaml` is the chart
  **default** — not a site.
- **Sites** live in `deploy/helm/sites/<chart>/<site-id>/values.yaml`. Each holds
  only the per-site overrides layered on top of the chart default at install
  time. `<site-id>` is lowercase and DNS-safe (e.g. `oopl-001`).

## Install / upgrade

Reference the site file with `--values`:

```bash
helm install sbc-<site-id> deploy/helm/sbc \
  -n sbc-system --create-namespace \
  --values deploy/helm/sites/sbc/<site-id>/values.yaml

helm install cc-<site-id> deploy/helm/central-config \
  -n central-config --create-namespace \
  --values deploy/helm/sites/central-config/<site-id>/values.yaml
```

See [../sbc/DEPLOYING.md](../sbc/DEPLOYING.md) for the full SBC site-deployment
guide and [../sbc/BOOTSTRAP.md](../sbc/BOOTSTRAP.md) for greenfield node bring-up.
