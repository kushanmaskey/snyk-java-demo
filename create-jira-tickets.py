#!/usr/bin/env python3
import json, os, sys, base64
import urllib.request, urllib.parse, urllib.error

JIRA_SITE   = 'https://snyk-java-demo.atlassian.net'
JIRA_EMAIL  = 'kushan.maskey@gmail.com'
JIRA_TOKEN  = os.environ.get('JIRA_API_TOKEN', '')
PROJECT_KEY = 'KAN'
SCA_JSON    = 'snyk-sca-report.json'
SAST_JSON   = 'snyk-sast-report.json'

PRIORITY_MAP = {'critical': 'Highest', 'high': 'High', 'medium': 'Medium', 'low': 'Low'}

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

def jira_post(path, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(f"{JIRA_SITE}/rest/api/3{path}",
                                  data=data, headers=headers(), method='POST')
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        print(f"  POST error {e.code}: {e.read().decode()[:200]}")
        return None

def find_ticket(label):
    jql    = f'project = "{PROJECT_KEY}" AND labels = "{label}"'
    result = jira_get(f'/search?jql={urllib.parse.quote(jql)}&maxResults=1')
    if result and result.get('total', 0) > 0:
        return result['issues'][0]
    return None

def jira_put(path, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(f"{JIRA_SITE}/rest/api/3{path}",
                                  data=data, headers=headers(), method='PUT')
    try:
        with urllib.request.urlopen(req) as r:
            return True
    except urllib.error.HTTPError as e:
        print(f"  PUT error {e.code}: {e.read().decode()[:200]}")
        return False

def adf(*paragraphs):
    return {
        'type': 'doc', 'version': 1,
        'content': [
            {'type': 'paragraph', 'content': [{'type': 'text', 'text': str(p)}]}
            for p in paragraphs if p and str(p).strip()
        ]
    }

def create_ticket(summary, paragraphs, severity, label):
    existing = find_ticket(label)
    if existing:
        issue_key    = existing['key']
        current_lbls = existing['fields'].get('labels', [])
        sev_label    = f'severity-{severity}'
        if sev_label not in current_lbls:
            new_labels = list(set(current_lbls + ['snyk-security', sev_label, label]))
            jira_put(f'/issue/{issue_key}', {'fields': {'labels': new_labels}})
            print(f"  UPDATED {issue_key}: added {sev_label}")
        else:
            print(f"  SKIP (exists): {label}")
        return
    body = {
        'fields': {
            'project':     {'key': PROJECT_KEY},
            'summary':     summary[:255],
            'description': adf(*paragraphs),
            'issuetype':   {'name': 'Task'},
            'priority':    {'name': PRIORITY_MAP.get(severity, 'Medium')},
            'labels':      ['snyk-security', f'severity-{severity}', label],
        }
    }
    result = jira_post('/issue', body)
    if result and result.get('key'):
        print(f"  CREATED {result['key']}: {summary[:80]}")
    else:
        print(f"  FAILED:  {summary[:80]}")

def process_sca():
    print("\n--- SCA Vulnerabilities ---")
    try:
        with open(SCA_JSON) as f:
            data = json.load(f)
        if isinstance(data, list):
            data = data[0] if data else {}
    except Exception as e:
        print(f"  Could not read {SCA_JSON}: {e}")
        return

    seen = set()
    for v in data.get('vulnerabilities', []):
        vid = v.get('id', '')
        if not vid or vid in seen:
            continue
        seen.add(vid)
        sev     = v.get('severity', 'low').lower()
        pkg     = v.get('moduleName', v.get('packageName', 'unknown'))
        version = v.get('version', '')
        fixed   = ', '.join(v.get('fixedIn', [])) or 'No fix available'
        cves    = ', '.join(v.get('identifiers', {}).get('CVE', [])) or vid
        cvss    = v.get('cvssScore', 'N/A')
        desc    = v.get('description', '')[:400]
        summary = f"[SECURITY/SCA] {v.get('title', vid)} — {pkg} {version}"
        paras   = [
            f"Snyk ID: {vid}",
            f"CVE: {cves}",
            f"Severity: {sev.upper()}  |  CVSS Score: {cvss}",
            f"Affected Package: {pkg} {version}",
            f"Remediation: Upgrade to {fixed}",
            f"Description: {desc}" if desc else '',
        ]
        label = f"snyk-{vid}"
        create_ticket(summary, paras, sev, label)

def process_sast():
    print("\n--- SAST Code Issues ---")
    try:
        with open(SAST_JSON) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  Could not read {SAST_JSON}: {e}")
        return

    sev_map = {'error': 'high', 'warning': 'medium', 'note': 'low'}
    for run in data.get('runs', []):
        rules = {r['id']: r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
        for result in run.get('results', []):
            rule_id = result.get('ruleId', '')
            rule    = rules.get(rule_id, {})
            sev     = sev_map.get(result.get('level', 'warning'), 'medium')
            locs    = result.get('locations', [])
            loc     = ''
            if locs:
                phys = locs[0].get('physicalLocation', {})
                uri  = phys.get('artifactLocation', {}).get('uri', '')
                line = phys.get('region', {}).get('startLine', '')
                loc  = f"{uri}:{line}" if line else uri
            msg     = result.get('message', {}).get('text', '')
            title   = rule.get('shortDescription', {}).get('text', rule_id)
            help_t  = rule.get('help', {}).get('text', '')[:300]
            cwes    = ', '.join(f"CWE-{c}" for c in rule.get('properties', {}).get('cwe', []))
            safe_loc = loc.replace('/', '-').replace(':', '-').replace('.', '-')
            label   = f"snyk-{rule_id}-{safe_loc}"[:80]
            summary = f"[SECURITY/SAST] {title} — {loc}"
            paras   = [
                f"Rule: {rule_id}",
                f"Severity: {sev.upper()}",
                f"CWE: {cwes}" if cwes else '',
                f"Location: {loc}",
                f"Issue: {msg}",
                f"Guidance: {help_t}" if help_t else '',
            ]
            create_ticket(summary, paras, sev, label)

if not JIRA_TOKEN:
    print("ERROR: JIRA_API_TOKEN environment variable not set.")
    sys.exit(1)

print("Creating JIRA tickets for Snyk findings...")
process_sca()
process_sast()
print("\nDone.")
