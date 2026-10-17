#!/usr/bin/env python3
import json, os
from datetime import datetime

# Accepted risks / false positives — excluded from dashboard counts and display.
IAC_ACCEPTED  = {('SNYK-CC-TF-1', 'ec2.tf'), ('SNYK-CC-TF-73', 'ec2.tf')}
SAST_ACCEPTED = {('java/Ssrf', 'src/main/java/com/example/App.java')}

SCA_JSON     = 'snyk-sca-report.json'
SAST_JSON    = 'snyk-sast-report.json'
IAC_JSON     = 'snyk-iac-report.json'
DAST_JSON    = 'zap-dast-report.json'
SECRETS_JSON = 'trufflehog-report.json'
OUTPUT       = '/opt/homebrew/Cellar/tomcat/11.0.25/libexec/webapps/ROOT/csd.html'

def parse_sca(path):
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            data = data[0] if data else {}
    except Exception:
        return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'vulns': []}

    vulns  = data.get('vulnerabilities', [])
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    seen, items = set(), []
    for v in vulns:
        sev = v.get('severity', 'low').lower()
        if sev in counts:
            counts[sev] += 1
        vid = v.get('id', '')
        if vid not in seen:
            seen.add(vid)
            cves = v.get('identifiers', {}).get('CVE', [])
            cwes = v.get('identifiers', {}).get('CWE', [])
            refs = [{'title': r.get('title', r.get('url', '')), 'url': r.get('url', '')}
                    for r in v.get('references', []) if r.get('url')]
            items.append({
                'id':          vid,
                'title':       v.get('title', 'Unknown'),
                'severity':    sev,
                'cvss':        v.get('cvssScore', ''),
                'package':     v.get('moduleName', v.get('packageName', 'Unknown')),
                'version':     v.get('version', ''),
                'fixedIn':     ', '.join(v.get('fixedIn', [])) or 'No fix available',
                'description': v.get('description', '')[:600],
                'cves':        cves,
                'cwes':        cwes,
                'from':        ' → '.join(v.get('from', [])),
                'refs':        refs[:4],
            })
    return {**counts, 'vulns': items}

CWE_REMEDIATION = {
    '22':  'Validate and canonicalize file paths. Use a whitelist of allowed directories and reject paths containing ".." or absolute paths from user input.',
    '78':  'Avoid passing user-controlled input to OS commands. Use language APIs instead of shell execution. If shell is required, whitelist allowed values and never concatenate raw input.',
    '79':  'Encode all output rendered in HTML. Use a templating engine with auto-escaping. Apply Content-Security-Policy headers.',
    '89':  'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.',
    '94':  'Avoid evaluating user-controlled input as code. Use safe data formats (JSON/XML) instead of eval or reflection.',
    '200': 'Restrict access to sensitive data. Apply the principle of least privilege and ensure proper authentication/authorization checks.',
    '295': 'Enable full certificate chain validation. Do not override or disable TLS hostname verification in production code.',
    '326': 'Use strong, modern encryption algorithms (AES-256, RSA-2048+). Avoid MD5, SHA-1, DES, and RC4.',
    '327': 'Replace broken or weak cryptographic algorithms with industry-standard alternatives. Use well-maintained crypto libraries.',
    '330': 'Use a cryptographically secure random number generator (e.g., java.security.SecureRandom) for security-sensitive values.',
    '502': 'Avoid deserializing data from untrusted sources. Use safe formats like JSON with schema validation instead of native serialization.',
    '601': 'Validate redirect URLs against a strict whitelist. Reject or encode URLs that point to external or unexpected domains.',
    '611': 'Disable external entity processing in XML parsers (set FEATURE_SECURE_PROCESSING). Use a safe XML parsing configuration.',
    '918': 'Validate and restrict URLs before making server-side requests. Use an allowlist of permitted hosts/schemes. Block requests to internal/private IP ranges.',
}

def sast_remediation(cwes, help_txt, rule_id):
    if help_txt:
        return help_txt
    for cwe in cwes:
        num = cwe.replace('CWE-', '')
        if num in CWE_REMEDIATION:
            return CWE_REMEDIATION[num]
    name = rule_id.split('/')[-1].lower()
    if 'ssrf' in name or 'requestforgery' in name:
        return CWE_REMEDIATION['918']
    if 'sql' in name or 'injection' in name:
        return CWE_REMEDIATION['89']
    if 'command' in name:
        return CWE_REMEDIATION['78']
    if 'xss' in name or 'script' in name:
        return CWE_REMEDIATION['79']
    if 'path' in name or 'traversal' in name:
        return CWE_REMEDIATION['22']
    if 'deserializ' in name:
        return CWE_REMEDIATION['502']
    if 'crypto' in name or 'cipher' in name:
        return CWE_REMEDIATION['327']
    return 'Review the flagged code and apply the principle of least privilege. Sanitize all external inputs and avoid trusting user-controlled data in security-sensitive operations.'

def parse_sast(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return {'high': 0, 'medium': 0, 'low': 0, 'issues': []}

    counts  = {'high': 0, 'medium': 0, 'low': 0}
    items   = []
    sev_map = {'error': 'high', 'warning': 'medium', 'note': 'low'}
    for run in data.get('runs', []):
        rules = {r['id']: r for r in run.get('tool', {}).get('driver', {}).get('rules', [])}
        for result in run.get('results', []):
            rule_id = result.get('ruleId', '')
            rule    = rules.get(rule_id, {})
            locs    = result.get('locations', [])
            loc     = ''
            uri     = ''
            if locs:
                phys = locs[0].get('physicalLocation', {})
                uri  = phys.get('artifactLocation', {}).get('uri', '')
                line = phys.get('region', {}).get('startLine', '')
                loc  = f"{uri}:{line}" if line else uri
            if (rule_id, uri) in SAST_ACCEPTED:
                continue
            sev     = sev_map.get(result.get('level', 'warning'), 'medium')
            counts[sev] += 1
            props    = rule.get('properties', {})
            cwes     = [f"CWE-{c}" for c in props.get('cwe', [])]
            help_txt = rule.get('help', {}).get('text', rule.get('fullDescription', {}).get('text', ''))
            items.append({
                'ruleId':      rule_id,
                'title':       rule.get('shortDescription', {}).get('text', rule_id),
                'severity':    sev,
                'message':     result.get('message', {}).get('text', ''),
                'location':    loc,
                'cwes':        cwes,
                'remediation': sast_remediation(cwes, help_txt[:600], rule_id),
            })
    return {**counts, 'issues': items}

def parse_iac(path):
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, list):
            data = [data]
    except Exception:
        return {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'issues': []}

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    items  = []
    for file_result in data:
        target = file_result.get('targetFile', '')
        for issue in file_result.get('infrastructureAsCodeIssues', []):
            if issue.get('isIgnored'):
                continue
            if (issue.get('id', ''), os.path.basename(target)) in IAC_ACCEPTED:
                continue
            sev = issue.get('severity', 'low').lower()
            if sev in counts:
                counts[sev] += 1
            resource_path = ' > '.join(str(p) for p in issue.get('path', []))
            remediation   = (issue.get('remediation', {}).get('terraform')
                             or issue.get('resolve', '')
                             or 'Review and apply the principle of least privilege to this resource.')
            items.append({
                'id':          issue.get('id', ''),
                'title':       issue.get('title', 'Unknown'),
                'severity':    sev,
                'subType':     issue.get('subType', 'IaC'),
                'issue':       issue.get('issue', issue.get('msg', '')),
                'impact':      issue.get('impact', ''),
                'remediation': remediation,
                'resource':    resource_path,
                'file':        target,
                'line':        issue.get('lineNumber', ''),
                'docs':        issue.get('documentation', ''),
            })
    return {**counts, 'issues': items}

def parse_dast(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return {'high': 0, 'medium': 0, 'low': 0, 'issues': []}

    risk_map = {'3': 'high', '2': 'medium', '1': 'low'}
    counts   = {'high': 0, 'medium': 0, 'low': 0}
    items    = []
    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            risk = str(alert.get('riskcode', '0'))
            sev  = risk_map.get(risk)
            if not sev:
                continue
            counts[sev] += 1
            instances = alert.get('instances', [])
            urls = list({inst.get('uri', '') for inst in instances[:5] if inst.get('uri')})
            items.append({
                'pluginid':  alert.get('pluginid', ''),
                'name':      alert.get('name', alert.get('alert', 'Unknown')),
                'severity':  sev,
                'desc':      alert.get('desc', '')[:500],
                'solution':  alert.get('solution', '')[:400],
                'url':       urls[0] if urls else '',
                'urls':      urls,
                'count':     alert.get('count', '0'),
                'cweid':     alert.get('cweid', ''),
                'wascid':    alert.get('wascid', ''),
                'reference': alert.get('reference', '')[:300],
            })
    items.sort(key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['severity'], 3))
    return {**counts, 'issues': items}

def parse_secrets(path):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f if l.strip()]
    except Exception:
        return {'high': 0, 'medium': 0, 'configured': False, 'findings': []}

    counts = {'high': 0, 'medium': 0}
    items  = []
    seen   = set()
    for line in lines:
        try:
            finding = json.loads(line)
        except Exception:
            continue
        detector = finding.get('DetectorName', 'Unknown')
        verified = finding.get('Verified', False)
        sev      = 'high' if verified else 'medium'
        meta     = finding.get('SourceMetadata', {}).get('Data', {})
        loc_data = (meta.get('Filesystem') or meta.get('Git') or meta.get('Github') or {})
        file_path = loc_data.get('file', loc_data.get('filename', 'unknown'))
        line_num  = loc_data.get('line', '')
        loc       = f"{file_path}:{line_num}" if line_num else file_path
        dedup_key = f"{detector}:{loc}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        counts[sev] += 1
        raw      = finding.get('Raw', '')
        redacted = raw[:4] + '****' if len(raw) > 4 else '****'
        items.append({
            'detector':  detector,
            'severity':  sev,
            'verified':  verified,
            'file':      file_path,
            'line':      line_num,
            'location':  loc,
            'redacted':  redacted,
            'decoder':   finding.get('DecoderName', ''),
        })
    items.sort(key=lambda x: 0 if x['severity'] == 'high' else 1)
    return {**counts, 'configured': True, 'findings': items}


def badge(sev):
    colors = {'critical': '#c0392b', 'high': '#e74c3c', 'medium': '#e67e22', 'low': '#3498db'}
    return f'<span class="badge" style="background:{colors.get(sev,"#95a5a6")}">{sev.upper()}</span>'

def esc(s):
    return str(s).replace('\\', '\\\\').replace('`', '\\`').replace('$', '\\$')

sca     = parse_sca(SCA_JSON)
sast    = parse_sast(SAST_JSON)
iac     = parse_iac(IAC_JSON)
dast    = parse_dast(DAST_JSON)
secrets = parse_secrets(SECRETS_JSON)

sca_total     = sca['critical'] + sca['high'] + sca['medium'] + sca['low']
sast_total    = sast['high'] + sast['medium'] + sast['low']
iac_total     = iac['critical'] + iac['high'] + iac['medium'] + iac['low']
dast_total    = dast['high'] + dast['medium'] + dast['low']
secrets_total = secrets['high'] + secrets['medium']
grand_total   = sca_total + sast_total + iac_total + dast_total + secrets_total
critical      = sca.get('critical', 0) + iac.get('critical', 0)
high          = (sca.get('high', 0) + sast.get('high', 0) + iac.get('high', 0)
                 + dast.get('high', 0) + secrets.get('high', 0))
high_crit     = critical + high
medium        = (sca.get('medium', 0) + sast.get('medium', 0) + iac.get('medium', 0)
                 + dast.get('medium', 0) + secrets.get('medium', 0))
low           = sca.get('low', 0) + sast.get('low', 0) + iac.get('low', 0) + dast.get('low', 0)
now           = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def dast_rows():
    if not dast['issues']:
        return '<tr><td colspan="5" class="empty">&#10003; No DAST findings</td></tr>'
    rows = []
    for i, issue in enumerate(dast['issues']):
        cwe_display = f"CWE-{issue['cweid']}" if issue['cweid'] else '—'
        rows.append(f'''<tr class="clickable" onclick="openDast({i})" title="Click for details">
        <td>{badge(issue["severity"])}</td>
        <td class="mono small">{issue["pluginid"]}</td>
        <td>{issue["name"]}</td>
        <td class="mono small">{cwe_display}</td>
        <td class="small">{issue["url"][:80]}</td>
    </tr>''')
    return ''.join(rows)

def sca_rows():
    if not sca['vulns']:
        return '<tr><td colspan="5" class="empty">&#10003; No vulnerabilities found</td></tr>'
    rows = []
    for i, v in enumerate(sca['vulns']):
        cve_display = ', '.join(v["cves"]) if v["cves"] else v["id"]
        rows.append(f'''<tr class="clickable" onclick="openSca({i})" title="Click for details">
        <td>{badge(v["severity"])}</td>
        <td class="mono small">{cve_display}</td>
        <td>{v["title"]}</td>
        <td class="mono small">{v["package"]} {v["version"]}</td>
        <td class="small">{v["fixedIn"]}</td>
    </tr>''')
    return ''.join(rows)

def sast_rows():
    if not sast['issues']:
        return '<tr><td colspan="5" class="empty">&#10003; No issues found</td></tr>'
    rows = []
    for i, issue in enumerate(sast['issues']):
        rows.append(f'''<tr class="clickable" onclick="openSast({i})" title="Click for details">
        <td>{badge(issue["severity"])}</td>
        <td class="mono small">{issue["ruleId"]}</td>
        <td>{issue["title"]}</td>
        <td class="small">{issue["message"][:120]}{"..." if len(issue["message"]) > 120 else ""}</td>
        <td class="mono small">{issue["location"]}</td>
    </tr>''')
    return ''.join(rows)

def iac_rows():
    if not iac['issues']:
        return '<tr><td colspan="5" class="empty">&#10003; No IaC issues found</td></tr>'
    rows = []
    for i, issue in enumerate(iac['issues']):
        rows.append(f'''<tr class="clickable" onclick="openIac({i})" title="Click for details">
        <td>{badge(issue["severity"])}</td>
        <td class="mono small">{issue["id"]}</td>
        <td>{issue["title"]}</td>
        <td class="small">{issue["subType"]}</td>
        <td class="mono small">{issue["file"]}</td>
    </tr>''')
    return ''.join(rows)

def secrets_rows():
    if not secrets['findings']:
        return '<tr><td colspan="5" class="empty">&#10003; No secrets found</td></tr>'
    rows = []
    for i, s in enumerate(secrets['findings']):
        verified_tag = '<span class="tag" style="background:#fdecea;color:#c0392b">VERIFIED</span>' if s['verified'] else '<span class="tag">UNVERIFIED</span>'
        rows.append(f'''<tr class="clickable" onclick="openSecrets({i})" title="Click for details">
        <td>{badge(s["severity"])}</td>
        <td>{s["detector"]}</td>
        <td>{verified_tag}</td>
        <td class="mono small">{s["file"]}</td>
        <td class="mono small">{s["redacted"]}</td>
    </tr>''')
    return ''.join(rows)


sca_json_str     = json.dumps(sca['vulns'],      ensure_ascii=False)
sast_json_str    = json.dumps(sast['issues'],    ensure_ascii=False)
iac_json_str     = json.dumps(iac['issues'],     ensure_ascii=False)
dast_json_str    = json.dumps(dast['issues'],    ensure_ascii=False)
secrets_json_str = json.dumps(secrets['findings'], ensure_ascii=False)

if secrets['configured']:
    secrets_tab_html = f'''<div class="pills">
    <span class="pill high">High (Verified): {secrets.get("high", 0)}</span>
    <span class="pill medium">Medium (Unverified): {secrets.get("medium", 0)}</span>
  </div>
  <table id="secrets-table">
    <thead><tr>
      <th onclick="sortTable('secrets-table',0,this)">Severity<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('secrets-table',1,this)">Detector<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('secrets-table',2,this)">Status<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('secrets-table',3,this)">File<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('secrets-table',4,this)">Redacted Value<i class="sort-arrow">⇅</i></th>
    </tr></thead>
    <tbody>{secrets_rows()}</tbody>
  </table>'''
else:
    unavailable_msg  = 'TruffleHog scan report not available for this build.'
    secrets_tab_html = f'<p style="color:#888;padding:20px">{unavailable_msg}</p>'

html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cyber Security Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #f4f5f7; color: #222; padding: 32px; }}
  header h1     {{ font-size: 24px; color: #111; }}
  header h1 span {{ color: #6c757d; font-size: 14px; font-weight: 400; }}
  header p      {{ color: #888; font-size: 13px; margin-top: 4px; }}

  .cards-row {{ display: flex; gap: 14px; margin-bottom: 14px; }}
  .card  {{ flex: 1; background: #fff; border: 1px solid #dde1e7; border-radius: 10px;
            padding: 18px 24px; text-align: center; }}
  .card .num {{ font-size: 38px; font-weight: 700; line-height: 1; }}
  .card .lbl {{ font-size: 11px; color: #999; margin-top: 6px; text-transform: uppercase; letter-spacing: .5px; }}
  .total .num {{ color: #222; }}
  .dast  .num {{ color: #16a085; }}
  .sca   .num {{ color: #e74c3c; }}
  .sast  .num {{ color: #e67e22; }}
  .iac     .num {{ color: #8e44ad; }}
  .secrets .num {{ color: #95a5a6; }}
  .crit  .num {{ color: #c0392b; }}
  .hc    .num {{ color: #e74c3c; }}
  .med   .num {{ color: #e67e22; }}
  .lw    .num {{ color: #3498db; }}

  .tabs       {{ display: flex; gap: 4px; }}
  .tab-btn    {{ padding: 10px 24px; border-radius: 8px 8px 0 0; border: 1px solid #dde1e7;
                 border-bottom: none; background: #e9ecef; color: #888; cursor: pointer;
                 font-size: 14px; font-weight: 600; transition: all .15s; }}
  .tab-btn:hover  {{ color: #444; }}
  .tab-btn.active {{ background: #fff; color: #111; border-color: #dde1e7; }}

  .tab-panel        {{ display: none; background: #fff; border: 1px solid #dde1e7;
                       border-radius: 0 8px 8px 8px; padding: 24px; }}
  .tab-panel.active {{ display: block; }}

  .pills {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }}
  .pill  {{ padding: 3px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
  .pill.critical {{ background: #fdecea; color: #c0392b; border: 1px solid #f5c6c2; }}
  .pill.high     {{ background: #fdecea; color: #e74c3c; border: 1px solid #f5c6c2; }}
  .pill.medium   {{ background: #fef6ec; color: #e67e22; border: 1px solid #fad7a0; }}
  .pill.low      {{ background: #eaf4fb; color: #2980b9; border: 1px solid #aed6f1; }}

  table    {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th       {{ text-align: left; padding: 9px 12px; color: #999; border-bottom: 1px solid #dde1e7;
              font-size: 11px; text-transform: uppercase; letter-spacing: .5px;
              cursor: pointer; user-select: none; white-space: nowrap; }}
  th:hover {{ color: #444; }}
  th .sort-arrow {{ margin-left: 4px; opacity: 0.3; font-style: normal; }}
  th.sort-asc  .sort-arrow,
  th.sort-desc .sort-arrow {{ opacity: 1; color: #2980b9; }}
  td       {{ padding: 9px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  .clickable {{ cursor: pointer; }}
  .clickable:hover td {{ background: #f0f4ff; }}

  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;
            color: #fff; white-space: nowrap; }}
  .mono  {{ font-family: monospace; }}
  .small {{ font-size: 12px; }}
  .empty {{ text-align: center; color: #27ae60; padding: 20px; }}

  /* Modal */
  .overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,.45);
              z-index: 100; align-items: center; justify-content: center; }}
  .overlay.open {{ display: flex; }}
  .modal  {{ background: #fff; border-radius: 12px; padding: 32px; max-width: 680px; width: 90%;
             max-height: 85vh; overflow-y: auto; position: relative; box-shadow: 0 8px 40px rgba(0,0,0,.18); }}
  .modal-close {{ position: absolute; top: 16px; right: 20px; font-size: 22px; cursor: pointer;
                  color: #aaa; border: none; background: none; line-height: 1; }}
  .modal-close:hover {{ color: #333; }}
  .modal h2   {{ font-size: 18px; color: #111; margin-bottom: 6px; padding-right: 32px; }}
  .modal-meta {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; align-items: center; }}
  .modal-section       {{ margin-bottom: 18px; }}
  .modal-section label {{ font-size: 11px; text-transform: uppercase; letter-spacing: .5px;
                          color: #999; display: block; margin-bottom: 4px; }}
  .modal-section p     {{ font-size: 13px; line-height: 1.6; color: #333; }}
  .modal-section .mono {{ font-size: 12px; background: #f4f5f7; padding: 8px 12px;
                          border-radius: 6px; display: block; }}
  .tag {{ display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 12px;
          font-weight: 600; background: #f0f0f0; color: #555; margin: 2px; }}
  .ref-link {{ display: block; font-size: 12px; color: #2980b9; margin: 3px 0;
               text-overflow: ellipsis; overflow: hidden; white-space: nowrap; }}
  .cvss-score {{ font-size: 22px; font-weight: 700; }}
  .remediation {{ background: #eafaf1; border-left: 4px solid #27ae60; border-radius: 6px;
                  padding: 12px 16px; margin-top: 4px; }}
  .remediation p {{ color: #1e8449; font-size: 13px; line-height: 1.6; }}
</style>
</head>
<body>

<header>
  <h1>Cyber Security Dashboard <span>CSD</span></h1>
  <p>Project: snyk-java-demo &nbsp;&middot;&nbsp; Scanned: {now}</p>
</header>

<div class="cards-row">
  <div class="card total"><div class="num">{grand_total}</div><div class="lbl">Total Issues</div></div>
</div>
<div class="cards-row">
  <div class="card dast">    <div class="num">{dast_total}</div><div class="lbl">DAST Issues</div></div>
  <div class="card iac">     <div class="num">{iac_total}</div> <div class="lbl">IaC Issues</div></div>
  <div class="card sca">     <div class="num">{sca_total}</div> <div class="lbl">SCA Issues</div></div>
  <div class="card sast">    <div class="num">{sast_total}</div><div class="lbl">SAST Issues</div></div>
  <div class="card secrets"> <div class="num">{'—' if not secrets['configured'] else secrets_total}</div><div class="lbl">Secrets</div></div>
</div>
<div class="cards-row">
  <div class="card crit"><div class="num">{critical}</div><div class="lbl">Critical</div></div>
  <div class="card hc">  <div class="num">{high}</div>    <div class="lbl">High</div></div>
  <div class="card med"> <div class="num">{medium}</div>  <div class="lbl">Medium</div></div>
  <div class="card lw">  <div class="num">{low}</div>     <div class="lbl">Low</div></div>
</div>

<div class="tabs">
  <button class="tab-btn active" onclick="showTab('dast', this)">DAST &mdash; Runtime ({dast_total})</button>
  <button class="tab-btn"        onclick="showTab('iac', this)">IaC &mdash; Infrastructure ({iac_total})</button>
  <button class="tab-btn"        onclick="showTab('sca', this)">SCA &mdash; Dependencies ({sca_total})</button>
  <button class="tab-btn"        onclick="showTab('sast', this)">SAST &mdash; Code Security ({sast_total})</button>
  <button class="tab-btn"        onclick="showTab('secrets', this)">Secrets ({secrets_total if secrets['configured'] else '—'})</button>
</div>

<div id="dast" class="tab-panel active">
  <div class="pills">
    <span class="pill high">High: {dast.get("high", 0)}</span>
    <span class="pill medium">Medium: {dast.get("medium", 0)}</span>
    <span class="pill low">Low: {dast.get("low", 0)}</span>
  </div>
  <table id="dast-table">
    <thead><tr>
      <th onclick="sortTable('dast-table',0,this)">Severity<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('dast-table',1,this)">Plugin ID<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('dast-table',2,this)">Alert<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('dast-table',3,this)">CWE<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('dast-table',4,this)">URL<i class="sort-arrow">⇅</i></th>
    </tr></thead>
    <tbody>{dast_rows()}</tbody>
  </table>
</div>

<div id="iac" class="tab-panel">
  <div class="pills">
    <span class="pill critical">Critical: {iac.get("critical", 0)}</span>
    <span class="pill high">High: {iac.get("high", 0)}</span>
    <span class="pill medium">Medium: {iac.get("medium", 0)}</span>
    <span class="pill low">Low: {iac.get("low", 0)}</span>
  </div>
  <table id="iac-table">
    <thead><tr>
      <th onclick="sortTable('iac-table',0,this)">Severity<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('iac-table',1,this)">Rule ID<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('iac-table',2,this)">Title<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('iac-table',3,this)">Resource<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('iac-table',4,this)">File<i class="sort-arrow">⇅</i></th>
    </tr></thead>
    <tbody>{iac_rows()}</tbody>
  </table>
</div>

<div id="sca" class="tab-panel">
  <div class="pills">
    <span class="pill critical">Critical: {sca.get("critical", 0)}</span>
    <span class="pill high">High: {sca.get("high", 0)}</span>
    <span class="pill medium">Medium: {sca.get("medium", 0)}</span>
    <span class="pill low">Low: {sca.get("low", 0)}</span>
  </div>
  <table id="sca-table">
    <thead><tr>
      <th onclick="sortTable('sca-table',0,this)">Severity<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sca-table',1,this)">CVE / ID<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sca-table',2,this)">Title<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sca-table',3,this)">Package<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sca-table',4,this)">Fixed In<i class="sort-arrow">⇅</i></th>
    </tr></thead>
    <tbody>{sca_rows()}</tbody>
  </table>
</div>

<div id="sast" class="tab-panel">
  <div class="pills">
    <span class="pill high">High: {sast.get("high", 0)}</span>
    <span class="pill medium">Medium: {sast.get("medium", 0)}</span>
    <span class="pill low">Low: {sast.get("low", 0)}</span>
  </div>
  <table id="sast-table">
    <thead><tr>
      <th onclick="sortTable('sast-table',0,this)">Severity<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sast-table',1,this)">Rule ID<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sast-table',2,this)">Title<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sast-table',3,this)">Message<i class="sort-arrow">⇅</i></th>
      <th onclick="sortTable('sast-table',4,this)">Location<i class="sort-arrow">⇅</i></th>
    </tr></thead>
    <tbody>{sast_rows()}</tbody>
  </table>
</div>

<div id="secrets" class="tab-panel">
  {secrets_tab_html}
</div>

<!-- Modal -->
<div class="overlay" id="overlay" onclick="closeModal(event)">
  <div class="modal" id="modal">
    <button class="modal-close" onclick="closeOverlay()">&times;</button>
    <h2 id="m-title"></h2>
    <div class="modal-meta" id="m-meta"></div>
    <div id="m-body"></div>
  </div>
</div>

<script>
const scaData     = {sca_json_str};
const sastData    = {sast_json_str};
const iacData     = {iac_json_str};
const dastData    = {dast_json_str};
const secretsData = {secrets_json_str};

function showTab(id, btn) {{
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}}

function sevColor(s) {{
  return {{critical:'#c0392b', high:'#e74c3c', medium:'#e67e22', low:'#3498db'}}[s] || '#999';
}}

function badgeHtml(s) {{
  return `<span class="badge" style="background:${{sevColor(s)}}">${{s.toUpperCase()}}</span>`;
}}

function openModal(title, metaHtml, bodyHtml) {{
  document.getElementById('m-title').innerHTML = title;
  document.getElementById('m-meta').innerHTML  = metaHtml;
  document.getElementById('m-body').innerHTML  = bodyHtml;
  document.getElementById('overlay').classList.add('open');
}}

function openDast(i) {{
  const v = dastData[i];
  const cweTag = v.cweid ? `<span class="tag">CWE-${{v.cweid}}</span>` : '';
  const wascTag = v.wascid ? `<span class="tag">WASC-${{v.wascid}}</span>` : '';
  const meta = `${{badgeHtml(v.severity)}} ${{cweTag}} ${{wascTag}}`;
  const urlList = v.urls.map(u => `<span class="mono" style="display:block;font-size:12px;margin:2px 0">${{u}}</span>`).join('');
  const body = `
    ${{v.url ? `<div class="modal-section"><label>Affected URL(s)</label>${{urlList || `<code class="mono">${{v.url}}</code>`}}</div>` : ''}}
    ${{v.desc ? `<div class="modal-section"><label>Description</label><p>${{v.desc}}</p></div>` : ''}}
    ${{v.solution ? `<div class="modal-section"><label>Solution</label><div class="remediation"><p>${{v.solution}}</p></div></div>` : ''}}
    ${{v.reference ? `<div class="modal-section"><label>References</label><p class="small">${{v.reference}}</p></div>` : ''}}`;
  openModal(v.name, meta, body);
}}

function openSca(i) {{
  const v = scaData[i];
  const cveLinks = v.cves.map(c => `<span class="tag">${{c}}</span>`).join(' ');
  const cweLinks = v.cwes.map(c => `<span class="tag">${{c}}</span>`).join(' ');
  const refHtml  = v.refs.map(r => `<a class="ref-link" href="${{r.url}}" target="_blank">${{r.title || r.url}}</a>`).join('');
  const meta = `
    ${{badgeHtml(v.severity)}}
    ${{v.cvss ? `<span class="cvss-score" style="color:${{sevColor(v.severity)}}">${{v.cvss}}</span><span style="font-size:12px;color:#999">CVSS</span>` : ''}}
    ${{cveLinks}}${{cweLinks}}`;
  const remediationText = v.fixedIn !== 'No fix available'
    ? `Upgrade <strong>${{v.package}}</strong> from version <strong>${{v.version}}</strong> to <strong>${{v.fixedIn}}</strong>. Update your <code>pom.xml</code> dependency version and rebuild.`
    : 'No fix is currently available. Monitor the package for future releases and consider alternative libraries.';
  const body = `
    <div class="modal-section"><label>Package</label><code class="mono">${{v.package}} ${{v.version}}</code></div>
    ${{v.from ? `<div class="modal-section"><label>Dependency Path</label><code class="mono">${{v.from}}</code></div>` : ''}}
    ${{v.description ? `<div class="modal-section"><label>Description</label><p>${{v.description}}</p></div>` : ''}}
    <div class="modal-section"><label>Remediation</label><div class="remediation"><p>${{remediationText}}</p></div></div>
    ${{refHtml ? `<div class="modal-section"><label>References</label>${{refHtml}}</div>` : ''}}`;
  openModal(v.title, meta, body);
}}

function openSast(i) {{
  const v = sastData[i];
  const cweHtml = v.cwes.map(c => `<span class="tag">${{c}}</span>`).join(' ');
  const meta = `${{badgeHtml(v.severity)}} ${{cweHtml}}`;
  const body = `
    <div class="modal-section"><label>Location</label><code class="mono">${{v.location}}</code></div>
    <div class="modal-section"><label>Issue</label><p>${{v.message}}</p></div>
    <div class="modal-section"><label>Remediation</label><div class="remediation"><p>${{v.remediation}}</p></div></div>`;
  openModal(v.title, meta, body);
}}

function openIac(i) {{
  const v = iacData[i];
  const meta = `${{badgeHtml(v.severity)}} <span class="tag">${{v.subType}}</span>`;
  const body = `
    <div class="modal-section"><label>Rule</label><code class="mono">${{v.id}}</code></div>
    <div class="modal-section"><label>Resource Path</label><code class="mono">${{v.resource}}</code></div>
    <div class="modal-section"><label>File</label><code class="mono">${{v.file}}${{v.line ? `:${{v.line}}` : ''}}</code></div>
    ${{v.issue ? `<div class="modal-section"><label>Issue</label><p>${{v.issue}}</p></div>` : ''}}
    ${{v.impact ? `<div class="modal-section"><label>Impact</label><p>${{v.impact}}</p></div>` : ''}}
    <div class="modal-section"><label>Remediation</label><div class="remediation"><p>${{v.remediation}}</p></div></div>
    ${{v.docs ? `<div class="modal-section"><label>Reference</label><a class="ref-link" href="${{v.docs}}" target="_blank">${{v.docs}}</a></div>` : ''}}`;
  openModal(v.title, meta, body);
}}


function openSecrets(i) {{
  const v = secretsData[i];
  const statusTag = v.verified
    ? `<span class="tag" style="background:#fdecea;color:#c0392b">VERIFIED</span>`
    : `<span class="tag">UNVERIFIED</span>`;
  const meta = `${{badgeHtml(v.severity)}} ${{statusTag}}`;
  const body = `
    <div class="modal-section"><label>Detector</label><code class="mono">${{v.detector}}</code></div>
    <div class="modal-section"><label>Location</label><code class="mono">${{v.location}}</code></div>
    <div class="modal-section"><label>Exposed Credential (redacted)</label><code class="mono">${{v.redacted}}</code></div>
    <div class="modal-section"><label>Remediation</label><div class="remediation"><p>
      Immediately <strong>revoke and rotate</strong> this ${{v.detector}} credential.
      Remove it from source code and use environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager).
      Audit git history — rotating the credential in the latest commit is not enough if it was previously pushed.
    </p></div></div>`;
  openModal(`${{v.detector}} Secret Found`, meta, body);
}}

const SEV_ORDER = {{'critical':0,'high':1,'medium':2,'low':3}};
function sortTable(tableId, col, th) {{
  const table  = document.getElementById(tableId);
  const tbody  = table.tBodies[0];
  const rows   = Array.from(tbody.rows);
  const allTh  = table.querySelectorAll('th');
  const asc    = !th.classList.contains('sort-asc');
  allTh.forEach(h => {{ h.classList.remove('sort-asc','sort-desc'); h.querySelector('.sort-arrow').textContent='⇅'; }});
  th.classList.add(asc ? 'sort-asc' : 'sort-desc');
  th.querySelector('.sort-arrow').textContent = asc ? '↑' : '↓';
  rows.sort((a, b) => {{
    let av = a.cells[col].textContent.trim().toLowerCase();
    let bv = b.cells[col].textContent.trim().toLowerCase();
    if (col === 0) {{ av = SEV_ORDER[av] ?? 9; bv = SEV_ORDER[bv] ?? 9; return asc ? av-bv : bv-av; }}
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

function closeModal(e) {{
  if (e.target === document.getElementById('overlay')) closeOverlay();
}}
function closeOverlay() {{
  document.getElementById('overlay').classList.remove('open');
}}
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeOverlay(); }});
</script>
</body>
</html>'''

with open(OUTPUT, 'w') as f:
    f.write(html)

print(f"CSD written to {OUTPUT}")
print(f"  DAST    — High:{dast.get('high',0)} Medium:{dast.get('medium',0)} Low:{dast.get('low',0)}")
print(f"  IaC     — Critical:{iac.get('critical',0)} High:{iac.get('high',0)} Medium:{iac.get('medium',0)} Low:{iac.get('low',0)}")
print(f"  SCA     — Critical:{sca.get('critical',0)} High:{sca.get('high',0)} Medium:{sca.get('medium',0)} Low:{sca.get('low',0)}")
print(f"  SAST    — High:{sast.get('high',0)} Medium:{sast.get('medium',0)} Low:{sast.get('low',0)}")
print(f"  Secrets — High:{secrets.get('high',0)} Medium:{secrets.get('medium',0)} (TruffleHog{'configured' if secrets['configured'] else 'not configured'})")
