#!/usr/bin/env python3
"""One-time cleanup: deletes all tickets from the KAN project."""
import json, os, sys, base64
import urllib.request, urllib.parse, urllib.error

JIRA_SITE   = 'https://snyk-java-demo.atlassian.net'
JIRA_EMAIL  = 'kushan.maskey@gmail.com'
JIRA_TOKEN  = os.environ.get('JIRA_API_TOKEN', '')
PROJECT_KEY = 'KAN'

def headers():
    token = base64.b64encode(f"{JIRA_EMAIL}:{JIRA_TOKEN}".encode()).decode()
    return {
        'Authorization': f'Basic {token}',
        'Content-Type':  'application/json',
        'Accept':        'application/json',
    }

def jira_get(path):
    req = urllib.request.Request(f"{JIRA_SITE}/rest/api/3{path}", headers=headers())
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  GET error {e.code}: {e.read().decode()[:200]}")
        return None

def jira_delete(issue_key):
    req = urllib.request.Request(
        f"{JIRA_SITE}/rest/api/3/issue/{issue_key}",
        headers=headers(), method='DELETE')
    try:
        with urllib.request.urlopen(req) as r:
            return True
    except urllib.error.HTTPError as e:
        print(f"  DELETE error {e.code} on {issue_key}: {e.read().decode()[:200]}")
        return False

if not JIRA_TOKEN:
    print("ERROR: JIRA_API_TOKEN environment variable not set.")
    sys.exit(1)

jql           = f'project = "{PROJECT_KEY}" ORDER BY created ASC'
total_deleted = 0

print("Deleting all tickets in KAN project...\n")
while True:
    # Always fetch from startAt=0 — deleted tickets drop off, next batch shifts up
    path   = f'/search/jql?jql={urllib.parse.quote(jql)}&maxResults=100&startAt=0&fields=summary'
    result = jira_get(path)
    if not result:
        break
    issues = result.get('issues', [])
    if not issues:
        break
    for issue in issues:
        key     = issue['key']
        summary = issue['fields']['summary'][:80]
        if jira_delete(key):
            print(f"  DELETED {key}: {summary}")
            total_deleted += 1
        else:
            print(f"  FAILED  {key}: {summary}")

print(f"\nDone. Deleted {total_deleted} tickets.")
print("Now run a Jenkins build to recreate them cleanly.")
