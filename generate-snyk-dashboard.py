#!/usr/bin/env python3
import json
from datetime import datetime

SCA_JSON  = 'snyk-sca-report.json'
SAST_JSON = 'snyk-sast-report.json'
OUTPUT    = '/opt/homebrew/Cellar/tomcat/11.0.25/libexec/webapps/ROOT/csd.html'

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
            items.append({
                'id':       vid,
                'title':    v.get('title', 'Unknown'),
                'severity': sev,
                'package':  v.get('moduleName', v.get('packageName', 'Unknown')),
                'version':  v.get('version', ''),
                'fixedIn':  ', '.join(v.get('fixedIn', [])) or 'No fix available',
            })
    return {**counts, 'vulns': items}

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
            sev     = sev_map.get(result.get('level', 'warning'), 'medium')
            counts[sev] += 1
            rule_id = result.get('ruleId', '')
            rule    = rules.get(rule_id, {})
            locs    = result.get('locations', [])
            loc     = ''
            if locs:
                phys = locs[0].get('physicalLocation', {})
                uri  = phys.get('artifactLocation', {}).get('uri', '')
                line = phys.get('region', {}).get('startLine', '')
                loc  = f"{uri}:{line}" if line else uri
            items.append({
                'ruleId':   rule_id,
                'title':    rule.get('shortDescription', {}).get('text', rule_id),
                'severity': sev,
                'message':  result.get('message', {}).get('text', '')[:200],
                'location': loc,
            })
    return {**counts, 'issues': items}

def badge(sev):
    colors = {'critical': '#c0392b', 'high': '#e74c3c', 'medium': '#e67e22', 'low': '#3498db'}
    return f'<span class="badge" style="background:{colors.get(sev,"#95a5a6")}">{sev.upper()}</span>'

sca  = parse_sca(SCA_JSON)
sast = parse_sast(SAST_JSON)

sca_total   = sca['critical'] + sca['high'] + sca['medium'] + sca['low']
sast_total  = sast['high'] + sast['medium'] + sast['low']
grand_total = sca_total + sast_total
high_crit   = sca.get('critical', 0) + sca.get('high', 0) + sast.get('high', 0)
medium      = sca.get('medium', 0) + sast.get('medium', 0)
low         = sca.get('low', 0) + sast.get('low', 0)
now         = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def sca_rows():
    if not sca['vulns']:
        return '<tr><td colspan="5" class="empty">&#10003; No vulnerabilities found</td></tr>'
    return ''.join(f'''<tr>
        <td>{badge(v["severity"])}</td>
        <td class="mono small">{v["id"]}</td>
        <td>{v["title"]}</td>
        <td class="mono small">{v["package"]} {v["version"]}</td>
        <td class="small">{v["fixedIn"]}</td>
    </tr>''' for v in sca['vulns'])

def sast_rows():
    if not sast['issues']:
        return '<tr><td colspan="5" class="empty">&#10003; No issues found</td></tr>'
    return ''.join(f'''<tr>
        <td>{badge(i["severity"])}</td>
        <td class="mono small">{i["ruleId"]}</td>
        <td>{i["title"]}</td>
        <td class="small">{i["message"]}</td>
        <td class="mono small">{i["location"]}</td>
    </tr>''' for i in sast['issues'])

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
  header h1 span {{ color: #6c757d; }}
  header p      {{ color: #888; font-size: 13px; margin-top: 4px; }}

  .cards {{ display: flex; flex-wrap: wrap; gap: 14px; margin: 28px 0; }}
  .card  {{ background: #fff; border: 1px solid #dde1e7; border-radius: 10px;
            padding: 18px 24px; text-align: center; min-width: 120px; }}
  .card .num {{ font-size: 38px; font-weight: 700; line-height: 1; }}
  .card .lbl {{ font-size: 11px; color: #999; margin-top: 6px; text-transform: uppercase; letter-spacing: .5px; }}
  .total .num {{ color: #222; }}
  .sca   .num {{ color: #e74c3c; }}
  .sast  .num {{ color: #e67e22; }}
  .hc    .num {{ color: #e74c3c; }}
  .med   .num {{ color: #e67e22; }}
  .lw    .num {{ color: #3498db; }}

  .tabs        {{ display: flex; gap: 4px; margin-bottom: 0; }}
  .tab-btn     {{ padding: 10px 24px; border-radius: 8px 8px 0 0; border: 1px solid #dde1e7;
                  border-bottom: none; background: #e9ecef; color: #888; cursor: pointer;
                  font-size: 14px; font-weight: 600; transition: all .15s; }}
  .tab-btn:hover   {{ color: #444; }}
  .tab-btn.active  {{ background: #fff; color: #111; border-color: #dde1e7; }}

  .tab-panel   {{ display: none; background: #fff; border: 1px solid #dde1e7;
                  border-radius: 0 8px 8px 8px; padding: 24px; }}
  .tab-panel.active {{ display: block; }}

  .pills {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }}
  .pill  {{ padding: 3px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
  .pill.critical {{ background: #fdecea; color: #c0392b; border: 1px solid #f5c6c2; }}
  .pill.high     {{ background: #fdecea; color: #e74c3c; border: 1px solid #f5c6c2; }}
  .pill.medium   {{ background: #fef6ec; color: #e67e22; border: 1px solid #fad7a0; }}
  .pill.low      {{ background: #eaf4fb; color: #2980b9; border: 1px solid #aed6f1; }}

  table  {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th     {{ text-align: left; padding: 9px 12px; color: #999; border-bottom: 1px solid #dde1e7;
            font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }}
  td     {{ padding: 9px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #f8f9fa; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700;
            color: #fff; white-space: nowrap; }}
  .mono  {{ font-family: monospace; }}
  .small {{ font-size: 12px; }}
  .empty {{ text-align: center; color: #27ae60; padding: 20px; }}
</style>
</head>
<body>

<header>
  <h1>Cyber Security Dashboard <span style="font-size:14px;color:#666;font-weight:400">CSD</span></h1>
  <p>Project: snyk-java-demo &nbsp;&middot;&nbsp; Scanned: {now}</p>
</header>

<div class="cards">
  <div class="card total"><div class="num">{grand_total}</div><div class="lbl">Total Issues</div></div>
  <div class="card sca">  <div class="num">{sca_total}</div> <div class="lbl">SCA Issues</div></div>
  <div class="card sast"> <div class="num">{sast_total}</div><div class="lbl">SAST Issues</div></div>
  <div class="card hc">   <div class="num">{high_crit}</div> <div class="lbl">High / Critical</div></div>
  <div class="card med">  <div class="num">{medium}</div>    <div class="lbl">Medium</div></div>
  <div class="card lw">   <div class="num">{low}</div>       <div class="lbl">Low</div></div>
</div>

<div class="tabs">
  <button class="tab-btn active" onclick="showTab('sca', this)">
    SCA &mdash; Dependencies ({sca_total})
  </button>
  <button class="tab-btn" onclick="showTab('sast', this)">
    SAST &mdash; Code Security ({sast_total})
  </button>
</div>

<div id="sca" class="tab-panel active">
  <div class="pills">
    <span class="pill critical">Critical: {sca.get("critical", 0)}</span>
    <span class="pill high">High: {sca.get("high", 0)}</span>
    <span class="pill medium">Medium: {sca.get("medium", 0)}</span>
    <span class="pill low">Low: {sca.get("low", 0)}</span>
  </div>
  <table>
    <thead><tr>
      <th>Severity</th><th>CVE / ID</th><th>Title</th><th>Package</th><th>Fixed In</th>
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
  <table>
    <thead><tr>
      <th>Severity</th><th>Rule ID</th><th>Title</th><th>Message</th><th>Location</th>
    </tr></thead>
    <tbody>{sast_rows()}</tbody>
  </table>
</div>

<script>
function showTab(id, btn) {{
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}}
</script>
</body>
</html>'''

with open(OUTPUT, 'w') as f:
    f.write(html)

print(f"CSD written to {OUTPUT}")
print(f"  SCA  — Critical:{sca.get('critical',0)} High:{sca.get('high',0)} Medium:{sca.get('medium',0)} Low:{sca.get('low',0)}")
print(f"  SAST — High:{sast.get('high',0)} Medium:{sast.get('medium',0)} Low:{sast.get('low',0)}")
