#!/usr/bin/env python
"""
Diagnostic test for Jira configuration
"""
import os
import requests
import base64
from datetime import datetime

JIRA_API_URL = os.getenv("JIRA_API_URL", "").strip()
JIRA_API_KEY = os.getenv("JIRA_API_KEY", "").strip()
JIRA_EMAIL = os.getenv("JIRA_EMAIL", "").strip()
JIRA_ISSUE_KEY = os.getenv("JIRA_ISSUE_KEY", "").strip()

print("=" * 70)
print("JIRA CONFIGURATION DIAGNOSTIC TEST")
print("=" * 70)

print(f"\n📋 Environment Variables:")
print(f"  JIRA_API_URL: {JIRA_API_URL}")
print(f"  JIRA_EMAIL: {JIRA_EMAIL}")
print(f"  JIRA_ISSUE_KEY: {JIRA_ISSUE_KEY}")
print(f"  JIRA_API_KEY (first 30 chars): {JIRA_API_KEY[:30]}...")

print(f"\n🔍 API Key Analysis:")
print(f"  Format appears to be: {JIRA_API_KEY[:20]}...")
if ':' in JIRA_API_KEY:
    print(f"  ⚠️  Contains colon - might be 'user_id:token' format")
    print(f"  First part: {JIRA_API_KEY.split(':')[0]}")
    print(f"  Second part: {JIRA_API_KEY.split(':')[1][:20]}...")

# Test 1: Direct basic auth
print(f"\n🧪 Test 1: Direct Basic Auth (email:api_key)")
try:
    url = f"{JIRA_API_URL.rstrip('/')}/rest/api/3/myself"
    response = requests.get(url, auth=(JIRA_EMAIL, JIRA_API_KEY), timeout=10)
    print(f"  Status: {response.status_code}")
    if response.status_code == 200:
        print(f"  ✅ SUCCESS")
        print(f"  User: {response.json().get('displayName')}")
    else:
        print(f"  ❌ FAILED - {response.status_code}")
except Exception as e:
    print(f"  ❌ ERROR: {str(e)[:100]}")

# Test 2: With manual Basic auth header
print(f"\n🧪 Test 2: Manual Authorization Header")
try:
    creds = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_API_KEY}".encode()).decode()
    url = f"{JIRA_API_URL.rstrip('/')}/rest/api/3/myself"
    headers = {"Authorization": f"Basic {creds}"}
    response = requests.get(url, headers=headers, timeout=10)
    print(f"  Status: {response.status_code}")
    if response.status_code == 200:
        print(f"  ✅ SUCCESS")
        print(f"  User: {response.json().get('displayName')}")
    else:
        print(f"  ❌ FAILED - {response.status_code}")
except Exception as e:
    print(f"  ❌ ERROR: {str(e)[:100]}")

# Test 3: Bearer token (if API key is a token)
print(f"\n🧪 Test 3: Bearer Token")
try:
    url = f"{JIRA_API_URL.rstrip('/')}/rest/api/3/myself"
    headers = {"Authorization": f"Bearer {JIRA_API_KEY}"}
    response = requests.get(url, headers=headers, timeout=10)
    print(f"  Status: {response.status_code}")
    if response.status_code == 200:
        print(f"  ✅ SUCCESS")
        print(f"  User: {response.json().get('displayName')}")
    else:
        print(f"  ❌ FAILED - {response.status_code}")
except Exception as e:
    print(f"  ❌ ERROR: {str(e)[:100]}")

# Test 4: Check if URL is accessible
print(f"\n🧪 Test 4: URL Accessibility")
try:
    url = JIRA_API_URL.rstrip('/')
    response = requests.get(url, timeout=10, allow_redirects=True)
    print(f"  Status: {response.status_code}")
    if response.status_code < 400:
        print(f"  ✅ URL is accessible")
    else:
        print(f"  ⚠️  URL returned {response.status_code}")
except Exception as e:
    print(f"  ❌ ERROR: {str(e)[:100]}")

print("\n" + "=" * 70)
print("⚠️  RECOMMENDATIONS:")
print("=" * 70)
print("""
1. Verify your Jira instance URL is correct
2. Check if using Jira Cloud (atlassian.net) or On-Premise
3. For Jira Cloud: Use email + API Token (from account.atlassian.com)
4. For Jira On-Premise: Use username + password or personal API token
5. Ensure API key/token hasn't expired
6. Verify the email address has access to the RPN project
7. Check if network connectivity allows access to Jira instance
""")
print("=" * 70 + "\n")
