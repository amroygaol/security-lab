#!/usr/bin/env python
"""
Simple test to validate Jira data fetching
"""
import os
import requests
import json
from datetime import datetime

JIRA_API_URL = os.getenv("JIRA_API_URL", "").strip()
JIRA_API_KEY = os.getenv("JIRA_API_KEY", "").strip()
JIRA_EMAIL = os.getenv("JIRA_EMAIL", "").strip()
JIRA_ISSUE_KEY = os.getenv("JIRA_ISSUE_KEY", "").strip()

print("=" * 70)
print("JIRA SAMPLE DATA TEST")
print("=" * 70)

print(f"\n📋 Configuration:")
print(f"  URL: {JIRA_API_URL}")
print(f"  Project: {JIRA_ISSUE_KEY}")
print(f"  Email: {JIRA_EMAIL}")

# Calculate date range
current_year = datetime.now().year
start_date = f"{current_year}-01-01"
end_date = datetime.now().strftime("%Y-%m-%d")

jql = f"project = {JIRA_ISSUE_KEY} AND created >= {start_date} AND created <= {end_date} ORDER BY created DESC"
print(f"\n🔍 JQL Query:")
print(f"  {jql}")

# Fetch tickets
search_url = f"{JIRA_API_URL.rstrip('/')}/rest/api/2/search"
headers = {
    "Accept": "application/json",
    "Authorization": f"Bearer {JIRA_API_KEY}",
    "Content-Type": "application/json"
}

params = {
    "jql": jql,
    "maxResults": 5,
    "fields": "key,summary,description,status,created,updated,reporter,assignee,priority,issuetype,labels"
}

print(f"\n📡 Making API request...")
print(f"  URL: {search_url}")

try:
    response = requests.get(search_url, headers=headers, params=params, timeout=30)
    print(f"  Status: {response.status_code}")
    print(f"  Response Length: {len(response.text)} bytes")
    
    if response.status_code == 200:
        # Try to parse JSON
        try:
            data = response.json()
            total = data.get("total", 0)
            issues = data.get("issues", [])
            
            print(f"\n✅ SUCCESS - Found {total} total tickets | Displaying {len(issues)} samples:\n")
            
            if issues:
                for idx, issue in enumerate(issues, 1):
                    print(f"[{idx}] {issue['key']}: {issue['fields'].get('summary', 'N/A')[:60]}")
                    print(f"    Type: {issue['fields']['issuetype']['name']:15} | Status: {issue['fields']['status']['name']}")
                    print(f"    Priority: {issue['fields'].get('priority', {}).get('name', 'N/A'):10} | Created: {issue['fields'].get('created', 'N/A')[:10]}")
                    if issue['fields'].get('assignee'):
                        print(f"    Assignee: {issue['fields']['assignee'].get('displayName', 'N/A')}")
                    print()
            else:
                print("⚠️  No tickets found in the date range.")
                
        except json.JSONDecodeError as e:
            print(f"\n⚠️  Response is not valid JSON: {e}")
            print(f"  Response preview: {response.text[:200]}")
    else:
        print(f"\n❌ API returned {response.status_code}")
        print(f"  Response: {response.text[:300]}")
        
except Exception as e:
    print(f"\n❌ Error: {e}")

print("\n" + "=" * 70)
