# USG Unified Communications SBC - Operational Runbook

## Overview

This runbook provides operational procedures for the USG UC Session Border Controller (SBC).

**NIST 800-53 Rev5 Controls:**
- **IR-4**: Incident Handling
- **IR-6**: Incident Reporting
- **CP-2**: Contingency Plan
- **CP-10**: System Recovery and Reconstitution

---

## Quick Reference

### Ports

| Port | Protocol | Service |
|------|----------|---------|
| 5060 | UDP/TCP | SIP |
| 5061 | TCP | SIP TLS |
| 8080 | TCP | HTTP API |
| 8443 | TCP | HTTPS API |
| 9090 | TCP | Prometheus metrics |
| 16384-32768 | UDP | RTP media |

### Health Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/health/live` | Kubernetes liveness probe |
| `/health/ready` | Kubernetes readiness probe |
| `/health` | Full health status |
| `/metrics` | Prometheus metrics |

---

## Deployment

### Docker

```bash
# Build
docker build -t sbc-daemon:latest .

# Run (development)
docker run -d \
  --name sbc \
  -p 5060:5060/udp \
  -p 5060:5060/tcp \
  -p 5061:5061/tcp \
  -p 8080:8080/tcp \
  -v ./config.toml:/etc/sbc/config.toml:ro \
  sbc-daemon:latest

# Run (with TLS certificates)
docker run -d \
  --name sbc \
  -p 5060:5060/udp \
  -p 5060:5060/tcp \
  -p 5061:5061/tcp \
  -p 8080:8080/tcp \
  -p 8443:8443/tcp \
  -v ./config.toml:/etc/sbc/config.toml:ro \
  -v ./certs:/etc/sbc/certs:ro \
  sbc-daemon:latest
```

### Kubernetes (Raw Manifests)

```bash
# Create namespace and deploy
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
kubectl apply -f deploy/kubernetes/pdb.yaml
kubectl apply -f deploy/kubernetes/networkpolicy.yaml

# Verify deployment
kubectl get pods -n sbc-system
kubectl get svc -n sbc-system
```

### Kubernetes (Helm)

```bash
# Install
helm install sbc ./deploy/helm/sbc -n sbc-system --create-namespace

# Install with custom values
helm install sbc ./deploy/helm/sbc \
  -n sbc-system \
  --create-namespace \
  -f custom-values.yaml

# Upgrade
helm upgrade sbc ./deploy/helm/sbc -n sbc-system -f custom-values.yaml

# Uninstall
helm uninstall sbc -n sbc-system
```

---

## Operations

### Configuration Hot-Reload

The SBC supports configuration hot-reload via SIGHUP signal:

```bash
# Docker
docker kill --signal=HUP sbc

# Kubernetes
kubectl exec -n sbc-system deployment/sbc-daemon -- kill -HUP 1

# Systemd
systemctl reload sbc-daemon
```

**Note:** Not all configuration changes can be applied without restart. Changes that require restart:
- Transport listen addresses
- TLS certificate paths
- Maximum calls/registrations limits

### Graceful Shutdown

The SBC performs graceful shutdown with connection draining:

1. Stop accepting new calls/registrations
2. Wait for active calls to complete (up to grace period)
3. Close remaining connections
4. Exit cleanly

Default grace period: 60 seconds (configurable via `terminationGracePeriodSeconds`)

```bash
# Docker
docker stop --time=60 sbc

# Kubernetes (automatic via terminationGracePeriodSeconds)
kubectl delete pod <pod-name> -n sbc-system
```

### Scaling

```bash
# Manual scaling
kubectl scale deployment/sbc-daemon -n sbc-system --replicas=4

# Enable HPA
helm upgrade sbc ./deploy/helm/sbc -n sbc-system \
  --set autoscaling.enabled=true \
  --set autoscaling.minReplicas=2 \
  --set autoscaling.maxReplicas=10
```

---

## Monitoring

### Prometheus Metrics

Key metrics to monitor:

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `sbc_active_calls` | Current active calls | > 80% of max_calls |
| `sbc_active_registrations` | Current registrations | > 80% of max_registrations |
| `sbc_sip_requests_total` | SIP requests by method | Sudden drops |
| `sbc_sip_responses_total` | SIP responses by code | 5xx > 1% |
| `sbc_rtp_packets_total` | RTP packets | Packet loss > 1% |
| `sbc_rate_limited_requests` | Rate limited requests | > 0 (investigate) |

### Prometheus Alerts

```yaml
groups:
  - name: sbc-alerts
    rules:
      - alert: SbcHighCallLoad
        expr: sbc_active_calls / sbc_max_calls > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "SBC call capacity above 80%"

      - alert: SbcHighErrorRate
        expr: rate(sbc_sip_responses_total{code=~"5.."}[5m]) / rate(sbc_sip_responses_total[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "SBC SIP 5xx error rate above 1%"

      - alert: SbcRateLimiting
        expr: increase(sbc_rate_limited_requests[5m]) > 0
        labels:
          severity: warning
        annotations:
          summary: "SBC is rate limiting requests"
```

### Grafana Dashboard

Import the provided dashboard from `deploy/grafana/sbc-dashboard.json` (if available) or create panels for:

1. **Overview**: Active calls, registrations, RPS
2. **SIP**: Request/response rates by method/code
3. **Media**: RTP packets, SRTP encryption status
4. **Resources**: CPU, memory, network I/O
5. **Security**: Rate limiting, blocked IPs, TLS handshakes

---

## Troubleshooting

### Common Issues

#### Pod Not Starting

```bash
# Check events
kubectl describe pod -n sbc-system -l app.kubernetes.io/name=sbc

# Check logs
kubectl logs -n sbc-system -l app.kubernetes.io/name=sbc --previous

# Common causes:
# - Missing ConfigMap/Secret
# - Invalid configuration
# - Resource constraints
```

#### SIP Not Working

```bash
# Check service endpoints
kubectl get endpoints -n sbc-system sbc-sip

# Test UDP connectivity
nc -vzu <sbc-ip> 5060

# Test TCP connectivity
nc -vz <sbc-ip> 5060

# Check logs for SIP errors
kubectl logs -n sbc-system -l app.kubernetes.io/name=sbc | grep -i sip
```

#### High Latency

1. Check resource utilization (CPU/memory)
2. Check rate limiting metrics
3. Check network latency to upstream servers
4. Verify media mode (relay vs pass-through)

#### TLS Handshake Failures

```bash
# Test TLS connection
openssl s_client -connect <sbc-ip>:5061 -tls1_3

# Check certificate
kubectl get secret -n sbc-system sbc-certs -o yaml

# Verify CNSA 2.0 compliance (P-384 curve)
openssl s_client -connect <sbc-ip>:5061 -tls1_3 2>&1 | grep "Server Temp Key"
```

### Log Analysis

```bash
# Stream logs
kubectl logs -f -n sbc-system -l app.kubernetes.io/name=sbc

# Filter by level
kubectl logs -n sbc-system -l app.kubernetes.io/name=sbc | jq 'select(.level == "error")'

# Filter by call-id
kubectl logs -n sbc-system -l app.kubernetes.io/name=sbc | jq 'select(.call_id == "abc123")'
```

---

## Incident Response

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| P1 | Service outage | 15 min |
| P2 | Degraded service | 1 hour |
| P3 | Minor issue | 4 hours |
| P4 | Cosmetic/info | Next business day |

### P1: Complete Outage

1. **Assess**: Verify outage scope
   ```bash
   kubectl get pods -n sbc-system
   curl -s http://<sbc-ip>:8080/health
   ```

2. **Mitigate**: Failover to standby if available
   ```bash
   # Scale up healthy replicas
   kubectl scale deployment/sbc-daemon -n sbc-system --replicas=4
   ```

3. **Investigate**: Gather logs and metrics
   ```bash
   kubectl logs -n sbc-system -l app.kubernetes.io/name=sbc --since=1h > sbc-logs.txt
   ```

4. **Resolve**: Apply fix and verify
5. **Document**: Create incident report

### P2: Degraded Service

1. **Assess**: Identify affected functionality
2. **Mitigate**: Scale up or reduce load
3. **Investigate**: Check resource utilization and logs
4. **Resolve**: Apply fix
5. **Document**: Update runbook if needed

---

## Maintenance

### Certificate Rotation

1. Generate new P-384 certificates
2. Create new Kubernetes secret
3. Trigger config reload or rolling restart

```bash
# Generate new cert (CNSA 2.0 compliant)
openssl ecparam -genkey -name secp384r1 -out new-key.pem
openssl req -new -key new-key.pem -out new-csr.pem
# Sign with CA...

# Update secret
kubectl create secret tls sbc-certs-new \
  --cert=new-cert.pem \
  --key=new-key.pem \
  -n sbc-system

# Update deployment to use new secret
kubectl set env deployment/sbc-daemon \
  -n sbc-system \
  TLS_SECRET=sbc-certs-new

# Cleanup old secret after verification
kubectl delete secret sbc-certs-old -n sbc-system
```

### Version Upgrade

1. Review changelog for breaking changes
2. Test in staging environment
3. Perform rolling upgrade

```bash
# Helm upgrade
helm upgrade sbc ./deploy/helm/sbc \
  -n sbc-system \
  --set image.tag=v0.2.0

# Monitor rollout
kubectl rollout status deployment/sbc-daemon -n sbc-system

# Rollback if needed
helm rollback sbc -n sbc-system
```

### Backup and Recovery

**What to backup:**
- ConfigMaps
- Secrets (TLS certs, STIR/SHAKEN certs)
- Persistent registration data (if using external storage)

```bash
# Export configuration
kubectl get configmap sbc-config -n sbc-system -o yaml > sbc-config-backup.yaml
kubectl get secret sbc-certs -n sbc-system -o yaml > sbc-certs-backup.yaml
```

---

## Security

### CNSA 2.0 Compliance Checklist

- [ ] TLS 1.3 only (`min_tls_version = "1.3"`)
- [ ] P-384 curve (`curve = "P384"`)
- [ ] AES-256-GCM SRTP (`profile = "AeadAes256Gcm"`)
- [ ] SHA-384 DTLS fingerprint (`fingerprint_hash = "Sha384"`)
- [ ] ES384 for STIR/SHAKEN

### Security Hardening

1. **Network Policies**: Enabled by default
2. **Pod Security**: Restricted PSS enforced
3. **RBAC**: Minimal permissions
4. **Secrets**: TLS certs mounted read-only
5. **Container**: Non-root, read-only filesystem

### Audit Logging

Audit logs are written to stdout in JSON format when `audit_enabled = true`:

```bash
# View audit events
kubectl logs -n sbc-system -l app.kubernetes.io/name=sbc | jq 'select(.audit == true)'
```

---

## Contacts

| Role | Contact |
|------|---------|
| On-call Engineer | <oncall@example.com> |
| Platform Team | <platform@example.com> |
| Security Team | <security@example.com> |

---

## Appendix

### Configuration Reference

See [config.toml](../config/config.toml) for full configuration reference.

### CLI Reference

```bash
# Status
sbc-cli status

# Health check
sbc-cli health

# List active calls
sbc-cli calls list

# Show metrics
sbc-cli metrics

# Configuration validation
sbc-cli config validate -c /etc/sbc/config.toml
```
