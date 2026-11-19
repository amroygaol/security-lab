#!/usr/bin/env python
"""
Test script to validate Jira configuration and fetch sample data
"""
import os
import requests
from datetime import datetime

# Load config from environment
JIRA_API_URL = os.getenv("JIRA_API_URL", "").strip()
JIRA_API_KEY = os.getenv("JIRA_API_KEY", "").strip()
JIRA_EMAIL = os.getenv("JIRA_EMAIL", "").strip()
JIRA_ISSUE_KEY = os.getenv("JIRA_ISSUE_KEY", "").strip()

def test_jira_connection():
    """Test Jira API connection"""
    print("=" * 70)
    print("JIRA CONNECTION TEST")
    print("=" * 70)
    
    print(f"\n📋 Configuration:")
    print(f"  JIRA_API_URL: {JIRA_API_URL}")
    print(f"  JIRA_EMAIL: {JIRA_EMAIL}")
    print(f"  JIRA_ISSUE_KEY: {JIRA_ISSUE_KEY}")
    print(f"  JIRA_API_KEY: {JIRA_API_KEY[:20]}...***")
    
    if not all([JIRA_API_URL, JIRA_API_KEY, JIRA_EMAIL, JIRA_ISSUE_KEY]):
        print("\n❌ ERROR: Missing required environment variables!")
        return False
    
    # Test basic connection
    print("\n🔗 Testing connection...")
    url = f"{JIRA_API_URL}/rest/api/3/myself"
    try:
        headers = {"Authorization": f"Bearer {JIRA_API_KEY}"}
        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            user_data = response.json()
            print(f"✅ Connection successful!")
            print(f"   Authenticated as: {user_data.get('displayName')} ({user_data.get('emailAddress')})")
        else:
            print(f"❌ Authentication failed: HTTP {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False
    
    # Fetch sample tickets
    print(f"\n📥 Fetching sample tickets for project '{JIRA_ISSUE_KEY}'...")
    
    current_year = datetime.now().year
    start_date = f"{current_year}-01-01"
    end_date = datetime.now().strftime("%Y-%m-%d")
    
    jql = f"project = {JIRA_ISSUE_KEY} AND created >= {start_date} AND created <= {end_date} ORDER BY created DESC"
    print(f"   JQL: {jql}")
    
    search_url = f"{JIRA_API_URL}/rest/api/3/search"
    params = {
        "jql": jql,
        "maxResults": 5,
        "fields": "key,summary,description,status,created,updated,reporter,assignee,priority,issuetype,labels"
    }
    
    try:
        response = requests.get(
            search_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {JIRA_API_KEY}"
            },
            params=params,
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        
        total = data.get("total", 0)
        issues = data.get("issues", [])
        
        print(f"\n✅ Found {total} total tickets | Fetched {len(issues)} samples:")
        
        if issues:
            for idx, issue in enumerate(issues, 1):
                print(f"\n  [{idx}] {issue['key']}: {issue['fields'].get('summary', 'N/A')}")
                print(f"      Status: {issue['fields']['status']['name']}")
                print(f"      Type: {issue['fields']['issuetype']['name']}")
                print(f"      Priority: {issue['fields'].get('priority', {}).get('name', 'N/A')}")
                print(f"      Created: {issue['fields'].get('created', 'N/A')}")
                print(f"      Reporter: {issue['fields'].get('reporter', {}).get('displayName', 'N/A')}")
                print(f"      Assignee: {issue['fields'].get('assignee', {}).get('displayName', 'Unassigned')}")
                if issue['fields'].get('labels'):
                    print(f"      Labels: {', '.join(issue['fields']['labels'])}")
        else:
            print("\n⚠️  No tickets found in the specified date range.")
            
        return True
        
    except Exception as e:
        print(f"❌ Error fetching tickets: {e}")
        return False

if __name__ == "__main__":
    success = test_jira_connection()
    print("\n" + "=" * 70)
    if success:
        print("✅ TEST PASSED - Jira configuration is valid!")
    else:
        print("❌ TEST FAILED - Please check your Jira configuration.")
    print("=" * 70 + "\n")
