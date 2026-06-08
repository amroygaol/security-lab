# Imperva Data Collection Revamp - Complete Guide

## What Changed

The Imperva collector has been completely redesigned to handle the broken stats endpoint (`/stats` returning 404) with a **multi-method fallback strategy**.

### Collection Flow

```
┌─────────────────────────────────────────────┐
│ Start: Collect 170 protected websites       │
└────────────────────┬────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼────┐          ┌──────▼──────┐
    │ PHASE 1 │          │  PHASE 2    │
    │Sites    │          │Threat/      │
    │Inventory│          │Traffic Stats│
    └────┬────┘          └──────┬──────┘
         │                      │
         ▼                      ▼
    ✅ 170 Sites          TRY Method 1:
       (working)          Account-level stats
                          ↓
                        FAIL? TRY Method 2:
                          Per-site stats
                          ↓
                        FAIL? TRY Method 3:
                          Infer from rules
                          ↓
                        RESULT: metrics set
```

## Data Sources Priority

### ✅ Working Data (Sites Inventory)
- Site domain & display name
- Status (active, bypass, etc)
- SSL/TLS configuration
- WAF mode (blocking, alert, none)
- DDoS protection status
- Bot mitigation status
- ACL rules count
- Data center configuration

### ⚠️ Conditional Data (Threat/Traffic Stats)
**Method 1 (Preferred)**: Account-level stats endpoint
- Endpoint: `/stats` or `/stats/account` or `/account/stats`
- Single API call for whole account
- **Note**: Returns empty if endpoint not available for your account

**Method 2 (Fallback)**: Per-site stats
- Iterates through 170 sites
- Each needs separate API call
- More likely to timeout

**Method 3 (Last Resort)**: Inferred from rules
- Uses WAF rule activity as proxy
- Conservative baseline only

## Prometheus Metrics

### Sites (Always Available)
```
imperva_waf_sites_total                    # 170
imperva_waf_sites_active                   # Actively protected
imperva_waf_sites_bypassed                 # In bypass mode (at risk)
imperva_waf_sites_ssl_enabled              # Using SSL/TLS
imperva_waf_sites_blocking_mode            # WAF set to block
imperva_waf_sites_ddos_protection_enabled  # DDoS enabled
```

### Threat/Traffic Stats (May be 0 if unavailable)
```
imperva_waf_threats_total_30d              # 0 if stats unavailable
imperva_waf_threats_sql_injection_30d      # 0 if stats unavailable
imperva_waf_threats_xss_30d                # 0 if stats unavailable
imperva_waf_requests_total_30d             # 0 if stats unavailable
imperva_waf_requests_blocked_30d           # 0 if stats unavailable
imperva_waf_bandwidth_total_gb_30d         # 0 if stats unavailable
```

## Dashboard Behavior

### Threat Metrics Panels (IDs: 78-81)
- **Gray color** = 0 value (stats endpoint unavailable) ⚠️
- **Green color** = 1+ value (data available, no threats)
- **Orange/Red** = High threat count

### Sites Protection Panels (IDs: 70-77)
- **Always colored** = Data always available ✅
- Show real-time WAF posture

## Troubleshooting

### If all threat metrics still show 0:

**Step 1: Check logs**
```powershell
docker logs security-tools-exporter | Select-String "Imperva.*threat\|stats.*source"
```

**Step 2: Enable debug logging**
```yaml
# In docker-compose.yml:
- IMPERVA_DEBUG=true
```

**Step 3: Check Imperva account type**
- Contact Imperva support
- Verify if stats API is enabled for your account
- Confirm correct stats endpoint for your region

**Step 4: Try alternative endpoint**
```yaml
# In docker-compose.yml, try:
- IMPERVA_STATS_ENDPOINTS=/sites/stats,/api/v2/stats
```

## Testing the Collector

### Check Prometheus metrics directly:
```bash
curl http://localhost:9090/api/v1/query?query=imperva_waf_threats_total_30d
```

### Check Elasticsearch data:
```bash
curl -X GET "http://localhost:9200/security-imperva-sites/_search?size=5"
```

### Monitor collection in real-time:
```bash
docker logs -f security-tools-exporter | grep -i imperva
```

## Expected Behavior After Revamp

### ✅ Scenario 1: Account with stats enabled
```
imperva_waf_threats_total_30d = 12547         (actual data)
imperva_waf_threats_sql_injection_30d = 89    (actual data)
imperva_waf_requests_blocked_30d = 3421       (actual data)
```
Logs: "Imperva: threat/traffic stats (source=account-level): threats=12547..."

### ⚠️ Scenario 2: Stats endpoint unavailable
```
imperva_waf_threats_total_30d = 0             (data unavailable)
imperva_waf_threats_sql_injection_30d = 0    (data unavailable)
imperva_waf_requests_blocked_30d = 0         (data unavailable)
```
Logs: "Imperva: threat/traffic stats returned 0. This may indicate: ..."
Dashboard panels: **GRAY color** indicates known unavailability

## Architecture Notes

The revamped collector implements **graceful degradation**:
- Sites inventory works standalone ✅
- Threat stats are optional add-on
- Zero values are intentional signals, not errors
- Dashboard handles data unavailability gracefully

This approach ensures dashboard reliability even when stats endpoint is broken.

## Next Steps

1. **Verify collection completes without errors**
   ```bash
   docker logs security-tools-exporter | Select-String "collection completed"
   ```

2. **Check site data is persisted to Elasticsearch**
   ```bash
   curl -s http://localhost:9200/security-imperva-sites/_count | jq .count
   ```

3. **If threat stats are 0, contact Imperva support** with:
   - Account ID
   - Region
   - Error message from logs
   - Request confirmation that stats API is enabled

4. **Monitor dashboard for 24h** to see if any data appears

