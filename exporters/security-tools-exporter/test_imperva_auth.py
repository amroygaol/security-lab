"""Quick test of Imperva API authentication methods."""
import requests
import json

API_ID = "200452"
API_KEY = "8e2ef07b-653b-4ecf-b6cd-7051df9f9952"
ACCOUNT_ID = "2355547"
V1_URL = "https://my.imperva.com/api/prov/v1/sites/list"


def show(label, resp):
    j = resp.json()
    code = j.get("res", j.get("res_code", -1))
    msg = j.get("res_message", "")
    print(f"  HTTP {resp.status_code}  res={code}  msg={msg}")
    if int(code) == 0:
        sites = j.get("sites", [])
        print(f"  SUCCESS — {len(sites)} sites returned")
        for s in sites[:5]:
            sid = s.get("site_id")
            domain = s.get("domain", "N/A")
            status = s.get("status", "?")
            print(f"    [{sid}] {domain} ({status})")
        return True
    return False


# ── Test 1: v1 body-only auth ───────────────────────────────────
print("Test 1 — v1 body auth (api_id + api_key in POST body)")
r = requests.post(V1_URL, data={
    "api_id": API_ID,
    "api_key": API_KEY,
    "account_id": ACCOUNT_ID,
    "page_size": 5, "page_num": 0,
}, timeout=30)
ok = show("Test 1", r)
print()

# ── Test 2: v1 header auth ──────────────────────────────────────
print("Test 2 — v1 header auth (x-API-Id + x-API-Key)")
r = requests.post(V1_URL, data={
    "account_id": ACCOUNT_ID,
    "page_size": 5, "page_num": 0,
}, headers={
    "x-API-Id": API_ID,
    "x-API-Key": API_KEY,
}, timeout=30)
ok = show("Test 2", r) or ok
print()

# ── Test 3: v2 REST (GET) ───────────────────────────────────────
print("Test 3 — v2 REST API (api.imperva.com)")
try:
    r = requests.get(
        "https://api.imperva.com/site-management/v2/sites",
        headers={
            "x-API-Id": API_ID,
            "x-API-Key": API_KEY,
            "Accept": "application/json",
        },
        params={"accountId": ACCOUNT_ID, "pageSize": 5},
        timeout=30,
    )
    print(f"  HTTP {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        print(f"  SUCCESS — keys: {list(data.keys())}")
        ok = True
    else:
        print(f"  {r.text[:300]}")
except Exception as e:
    print(f"  Error: {e}")
print()

# ── Test 4: account/status (simpler endpoint) ───────────────────
print("Test 4 — account status (body auth)")
try:
    r = requests.post(
        "https://my.imperva.com/api/prov/v1/account",
        data={"api_id": API_ID, "api_key": API_KEY, "account_id": ACCOUNT_ID},
        timeout=30,
    )
    j = r.json()
    code = j.get("res", -1)
    msg = j.get("res_message", "")
    print(f"  HTTP {r.status_code}  res={code}  msg={msg}")
    if int(code) == 0:
        acct = j.get("account", j)
        print(f"  SUCCESS — account: {json.dumps(acct, indent=2)[:400]}")
        ok = True
except Exception as e:
    print(f"  Error: {e}")

print()
if ok:
    print("==> At least one auth method succeeded!")
else:
    print("==> All methods failed. Check credentials.")
