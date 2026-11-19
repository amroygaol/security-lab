#!/usr/bin/env python
"""
Debug Jira API requests
"""
import os
import requests
from datetime import datetime

JIRA_API_URL = os.getenv("JIRA_API_URL", "").strip()
JIRA_API_KEY = os.getenv("JIRA_API_KEY", "").strip()
JIRA_ISSUE_KEY = os.getenv("JIRA_ISSUE_KEY", "").strip()

print("=" * 70)
print("JIRA API DEBUG")
print("=" * 70)

# Try different URL formats
url_formats = [
    f"{JIRA_API_URL}/rest/api/3/search",
    f"{JIRA_API_URL.rstrip('/')}/rest/api/3/search",
    f"{JIRA_API_URL.rstrip('/')}/rest/api/2/search",
    "https://jira.bri.co.id/rest/api/3/search",
]

current_year = datetime.now().year
start_date = f"{current_year}-01-01"
end_date = datetime.now().strftime("%Y-%m-%d")
jql = f"project = {JIRA_ISSUE_KEY}"

for attempt, url in enumerate(url_formats, 1):
    print(f"\n🧪 Attempt {attempt}: {url}")
    
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {JIRA_API_KEY}",
    }
    
    params = {
        "jql": jql,
        "maxResults": 1,
        "fields": "key,summary"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        print(f"   Status: {response.status_code}")
        print(f"   Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"   Response size: {len(response.text)} bytes")
        
        if response.status_code == 200:
            if 'application/json' in response.headers.get('Content-Type', ''):
                try:
                    data = response.json()
                    print(f"   ✅ Valid JSON response!")
                    print(f"      Total: {data.get('total', 0)}")
                    break
                except:
                    pass
            else:
                print(f"   ⚠️  Returned HTML instead of JSON")
                print(f"      Preview: {response.text[:100]}")
    except Exception as e:
        print(f"   ❌ Error: {e}")

print("\n" + "=" * 70)
