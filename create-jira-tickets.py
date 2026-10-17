#!/usr/bin/env python3
import json, os, sys, base64, re
import urllib.request, urllib.parse, urllib.error

def strip_html(text):
    return re.sub(r'<[^>]+>', ' ', str(text)).strip()

JIRA_SITE   = 'https://snyk-java-demo.atlassian.net'
JIRA_EMAIL  = 'kushan.maskey@gmail.com'
JIRA_TOKEN  = os.environ.get('JIRA_API_TOKEN', '')
PROJECT_KEY = 'KAN'
SCA_JSON    = 'snyk-sca-report.json'
SAST_JSON   = 'snyk-sast-report.json'
IAC_JSON    = 'snyk-iac-report.json'
DAST_JSON    = 'zap-dast-report.json'
SECRETS_JSON = 'trufflehog-report.json'

PRIORITY_MAP = {'critical': 'Highest', 'high': 'High', 'medium': 'Medium', 'low': 'Low'}
SEV_ORDER    = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
TYPE_LABEL   = {'dast': 'type-0-dast', 'iac': 'type-1-iac', 'sca': 'type-2-sca', 'sast': 'type-3-sast', 'secrets': 'type-4-secrets'}

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
            body = r.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        print(f"  POST error {e.code}: {e.read().decode()[:200]}")
        return None

def fetch_existing_summaries():
    jql    = f'project = "{PROJECT_KEY}" AND statusCategory != Done ORDER BY created ASC'
    result_map = {}
    start  = 0
    while True:
        path   = f'/search/jql?jql={urllib.parse.quote(jql)}&maxResults=100&startAt={start}&fields=summary'
        result = jira_get(path)
        if not result:
            break
        issues = result.get('issues', [])
        if not issues:
            break
        for issue in issues:
            result_map[issue['fields']['summary'].strip()] = issue['key']
        start += len(issues)
        if start >= result.get('total', 0):
            break
    print(f"  Loaded {len(result_map)} existing open tickets.")
    return result_map

def para(text):
    return {'type': 'paragraph', 'content': [{'type': 'text', 'text': str(text)}]}

def heading(text, level=3):
    return {'type': 'heading', 'attrs': {'level': level}, 'content': [{'type': 'text', 'text': str(text)}]}

def panel(text, panel_type='success'):
    return {'type': 'panel', 'attrs': {'panelType': panel_type},
            'content': [para(text)]}

def build_adf(*nodes):
    return {'type': 'doc', 'version': 1,
            'content': [n for n in nodes if n]}

EXISTING = {}   # summary -> issue_key for all currently open tickets
SCANNED  = set() # summaries detected in the current scan run

def create_ticket(summary, adf_doc, severity, scan_type):
    key = summary[:255].strip()
    SCANNED.add(key)
    if key in EXISTING:
        print(f"  SKIP (exists): {summary[:80]}")
        return
    body = {
        'fields': {
            'project':     {'key': PROJECT_KEY},
            'summary':     summary[:255],
            'description': adf_doc,
            'issuetype':   {'name': 'Task'},
            'priority':    {'name': PRIORITY_MAP.get(severity, 'Medium')},
            'labels':      [TYPE_LABEL[scan_type]],
        }
    }
    result = jira_post('/issue', body)
    if result and result.get('key'):
        EXISTING[key] = result['key']
        print(f"  CREATED {result['key']}: {summary[:80]}")
    else:
        print(f"  FAILED:  {summary[:80]}")

def auto_close_resolved():
    print("\n--- Auto-closing resolved tickets ---")
    closed = 0
    for summary, issue_key in list(EXISTING.items()):
        if summary not in SCANNED:
            transitions = jira_get(f'/issue/{issue_key}/transitions')
            done_id = next(
                (t['id'] for t in (transitions or {}).get('transitions', [])
                 if t['name'].lower() in ('done', 'closed', 'resolved')),
                None
            )
            if not done_id:
                print(f"  SKIP (no Done transition): {issue_key}")
                continue
            comment = {
                'body': {
                    'type': 'doc', 'version': 1,
                    'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text':
                        'Automatically resolved — this issue was not detected in the latest scan. '
                        'The fix has been deployed and verified by the CI pipeline.'
                    }]}]
                }
            }
            jira_post(f'/issue/{issue_key}/comment', comment)
            jira_post(f'/issue/{issue_key}/transitions', {'transition': {'id': done_id}})
            print(f"  AUTO-CLOSED {issue_key}: {summary[:70]}")
            closed += 1
    print(f"  Auto-closed {closed} resolved tickets.")

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
    vulns = sorted(data.get('vulnerabilities', []),
                   key=lambda v: SEV_ORDER.get(v.get('severity', 'low').lower(), 3))
    for v in vulns:
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
        desc    = strip_html(v.get('description', ''))[:400]
        cve_id  = v.get('identifiers', {}).get('CVE', [vid])[0]
        summary  = f"[SECURITY/SCA] {v.get('title', vid)} ({cve_id}) — {pkg} {version}"
        fix_note = (f"Upgrade {pkg} from version {version} to {fixed}. "
                    f"Update your pom.xml dependency version and rebuild."
                    if fixed != 'No fix available'
                    else 'No fix is currently available. Monitor the package for future releases and consider an alternative library.')
        adf_doc  = build_adf(
            heading('Overview'),
            para(f"Snyk ID: {vid}  |  CVE: {cves}  |  Severity: {sev.upper()}  |  CVSS: {cvss}"),
            para(f"Affected Package: {pkg} {version}"),
            heading('Description') if desc else None,
            para(desc) if desc else None,
            heading('How to Fix'),
            panel(fix_note),
        )
        create_ticket(summary, adf_doc, sev, 'sca')

def process_sast():
    print("\n--- SAST Code Issues ---")
    try:
        with open(SAST_JSON) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  Could not read {SAST_JSON}: {e}")
        return

    sev_map  = {'error': 'high', 'warning': 'medium', 'note': 'low'}
    findings = []
    for run in data.get('runs', []):
        rules = {r['id']: r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
        for result in run.get('results', []):
            findings.append((result, rules))
    findings.sort(key=lambda x: SEV_ORDER.get(sev_map.get(x[0].get('level', 'warning'), 'medium'), 3))

    for result, rules in findings:
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
            summary = f"[SECURITY/SAST] {title} — {loc}"
            fix_note = help_t or 'Review the flagged code, sanitize all external inputs, and apply the principle of least privilege.'
            adf_doc = build_adf(
                heading('Overview'),
                para(f"Rule: {rule_id}  |  Severity: {sev.upper()}" + (f"  |  CWE: {cwes}" if cwes else '')),
                heading('Location'),
                para(loc),
                heading('Issue'),
                para(msg),
                heading('How to Fix'),
                panel(fix_note),
            )
            create_ticket(summary, adf_doc, sev, 'sast')

def process_dast():
    print("\n--- DAST Vulnerabilities ---")
    try:
        with open(DAST_JSON) as f:
            data = json.load(f)
    except Exception as e:
        print(f"  Could not read {DAST_JSON}: {e}")
        return

    risk_map   = {'3': 'high', '2': 'medium', '1': 'low'}
    all_alerts = []
    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            risk = str(alert.get('riskcode', '0'))
            if risk in risk_map:
                all_alerts.append(alert)
    all_alerts.sort(key=lambda a: int(a.get('riskcode', '0')), reverse=True)

    for alert in all_alerts:
        risk      = str(alert.get('riskcode', '0'))
        sev       = risk_map.get(risk, 'medium')
        name      = alert.get('name', alert.get('alert', 'Unknown'))
        plugin_id = alert.get('pluginid', '')
        cwe       = alert.get('cweid', '')
        wasc      = alert.get('wascid', '')
        desc      = strip_html(alert.get('desc', ''))[:400]
        solution  = strip_html(alert.get('solution', ''))[:400]
        instances = alert.get('instances', [])
        urls      = ', '.join(list({inst.get('uri', '') for inst in instances[:3] if inst.get('uri')}))
        summary  = f"[SECURITY/DAST] {name} (ZAP-{plugin_id})"
        fix_note = solution or 'Review the ZAP documentation for this plugin ID and apply the recommended security controls.'
        adf_doc  = build_adf(
            heading('Overview'),
            para(f"Plugin ID: {plugin_id}  |  Severity: {sev.upper()}"
                 + (f"  |  CWE: CWE-{cwe}" if cwe else '')
                 + (f"  |  WASC: {wasc}" if wasc else '')),
            heading('Affected URLs') if urls else None,
            para(urls) if urls else None,
            heading('Description') if desc else None,
            para(desc) if desc else None,
            heading('How to Fix'),
            panel(fix_note),
        )
        create_ticket(summary, adf_doc, sev, 'dast')

def process_iac():
    print("\n--- IaC Misconfigurations ---")
    try:
        with open(IAC_JSON) as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = [data]
    except Exception as e:
        print(f"  Could not read {IAC_JSON}: {e}")
        return

    all_issues = []
    for file_result in data:
        target = file_result.get('targetFile', '')
        for issue in file_result.get('infrastructureAsCodeIssues', []):
            if not issue.get('isIgnored'):
                all_issues.append((issue, target))
    all_issues.sort(key=lambda x: SEV_ORDER.get(x[0].get('severity', 'low').lower(), 3))

    for issue, target in all_issues:
            iid     = issue.get('id', '')
            sev     = issue.get('severity', 'low').lower()
            title   = issue.get('title', iid)
            subtype = issue.get('subType', 'IaC')
            path    = ' > '.join(str(p) for p in issue.get('path', []))
            issue_t = issue.get('issue', issue.get('msg', ''))
            impact  = issue.get('impact', '')
            resolve = (issue.get('remediation', {}).get('terraform')
                       or issue.get('resolve', ''))
            docs    = issue.get('documentation', '')
            summary  = f"[SECURITY/IAC] {title} ({iid}) — {path} ({target})"
            fix_note = resolve or 'Review this resource configuration and apply the principle of least privilege.'
            if docs:
                fix_note += f"\n\nReference: {docs}"
            adf_doc  = build_adf(
                heading('Overview'),
                para(f"Rule: {iid}  |  Severity: {sev.upper()}  |  Resource Type: {subtype}"),
                para(f"File: {target}  |  Resource: {path}"),
                heading('Issue') if issue_t else None,
                para(issue_t) if issue_t else None,
                heading('Impact') if impact else None,
                para(impact) if impact else None,
                heading('How to Fix'),
                panel(fix_note),
            )
            create_ticket(summary, adf_doc, sev, 'iac')

def process_secrets():
    print("\n--- Secret Scanning Findings ---")
    try:
        with open(SECRETS_JSON) as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception as e:
        print(f"  Could not read {SECRETS_JSON}: {e}")
        return

    findings = []
    for line in lines:
        try:
            findings.append(json.loads(line))
        except Exception:
            continue

    findings.sort(key=lambda x: 0 if x.get('Verified') else 1)

    seen = set()
    for finding in findings:
        detector = finding.get('DetectorName', 'Unknown')
        verified = finding.get('Verified', False)
        sev      = 'high' if verified else 'medium'
        raw      = finding.get('Raw', '')
        redacted = raw[:4] + '****' if len(raw) > 4 else '****'
        meta     = finding.get('SourceMetadata', {}).get('Data', {})
        loc_data = (meta.get('Filesystem') or meta.get('Git') or meta.get('Github') or {})
        file_path = loc_data.get('file', loc_data.get('filename', 'unknown'))
        line_num  = loc_data.get('line', '')
        loc       = f"{file_path}:{line_num}" if line_num else file_path
        dedup_key = f"{detector}:{loc}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        status   = 'VERIFIED' if verified else 'UNVERIFIED'
        summary  = f"[SECURITY/SECRETS] {detector} Secret Found — {file_path}"
        fix_note = (f"Immediately revoke and rotate the {detector} credential. "
                    f"Remove the secret from source code and use environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager). "
                    f"Audit git history and rotate any credentials that were ever committed.")
        adf_doc  = build_adf(
            heading('Overview'),
            para(f"Detector: {detector}  |  Status: {status}  |  Severity: {sev.upper()}"),
            heading('Location'),
            para(loc),
            heading('Exposed Credential'),
            para(f"Partial value: {redacted}"),
            heading('How to Fix'),
            panel(fix_note),
        )
        create_ticket(summary, adf_doc, sev, 'secrets')


if not JIRA_TOKEN:
    print("ERROR: JIRA_API_TOKEN environment variable not set.")
    sys.exit(1)

print("Creating JIRA tickets for Snyk findings...")
print("Loading existing tickets...")
EXISTING.update(fetch_existing_summaries())
process_dast()
process_iac()
process_sca()
process_sast()
process_secrets()
auto_close_resolved()
print("\nDone.")
