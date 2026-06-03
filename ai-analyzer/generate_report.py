# generate_report.py
# reads ai-report.json and generates a nice HTML security report

import json
import sys
from datetime import datetime
from pathlib import Path


def severity_color(severity: str) -> str:
    return {
        "critical": "#dc2626",
        "high":     "#ea580c",
        "medium":   "#d97706",
        "low":      "#65a30d",
    }.get(severity.lower(), "#6b7280")


def verdict_badge(verdict: str) -> str:
    styles = {
        "TRUE_POSITIVE":  ("background:#fee2e2;color:#991b1b;border:1px solid #fca5a5", "🔴 True Positive"),
        "FALSE_POSITIVE": ("background:#dcfce7;color:#166534;border:1px solid #86efac", "✅ False Positive"),
        "NEEDS_REVIEW":   ("background:#fef9c3;color:#854d0e;border:1px solid #fde047", "🟡 Needs Review"),
    }
    style, label = styles.get(verdict, ("background:#f3f4f6;color:#374151", verdict))
    return f'<span style="padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;{style}">{label}</span>'


def generate_html(report: dict, commit_sha: str = "", run_id: str = "") -> str:
    summary = report.get("summary", {})
    results = report.get("results", [])
    now     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    status       = summary.get("pipeline_status", "UNKNOWN")
    status_color = "#16a34a" if status == "PASS" else "#dc2626"
    status_icon  = "✅" if status == "PASS" else "❌"

    total    = summary.get("total_found", 0)
    tp       = summary.get("true_positives", 0)
    fp       = summary.get("false_positives", 0)
    nr       = summary.get("needs_review", 0)
    blocking = summary.get("blocking", 0)

    # build results rows
    rows = ""
    for r in results:
        sev   = r.get("severity", "unknown")
        rows += f"""
        <tr>
          <td><code style="font-size:12px">{r.get('id','')}</code></td>
          <td><span style="color:{severity_color(sev)};font-weight:700;text-transform:uppercase">{sev}</span></td>
          <td style="font-size:13px;max-width:200px;word-break:break-all">{r.get('type','').split('.')[-1]}</td>
          <td><code style="font-size:11px">{r.get('file','')}</code></td>
          <td>{verdict_badge(r.get('verdict',''))}</td>
          <td style="font-size:12px">{r.get('confidence',0)}%</td>
          <td style="font-size:12px;color:#4b5563">{r.get('explanation','')[:120]}{'...' if len(r.get('explanation','')) > 120 else ''}</td>
        </tr>"""
        if r.get("remediation"):
            rows += f"""
        <tr style="background:#f8fafc">
          <td colspan="7" style="padding:8px 16px">
            <strong style="color:#1d4ed8;font-size:12px">📝 Suggested fix:</strong>
            <pre style="margin:4px 0 0 0;padding:8px;background:#1e293b;color:#e2e8f0;border-radius:6px;font-size:11px;overflow-x:auto">{r.get('remediation','')[:500]}</pre>
          </td>
        </tr>"""

    commit_info = f'<span style="color:#6b7280;font-size:13px">Commit: <code>{commit_sha[:7] if commit_sha else "unknown"}</code></span>' if commit_sha else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Report — DevSecOps Pipeline</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f1f5f9; color: #1e293b; }}
    .header {{ background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 32px 40px; }}
    .header h1 {{ font-size: 24px; font-weight: 700; margin-bottom: 6px; }}
    .header p  {{ color: #94a3b8; font-size: 14px; }}
    .status-badge {{ display: inline-block; padding: 6px 18px; border-radius: 20px; font-weight: 700; font-size: 16px; margin-top: 16px; background: {status_color}; color: white; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .card {{ background: white; border-radius: 12px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }}
    .card .number {{ font-size: 36px; font-weight: 800; }}
    .card .label  {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
    .section {{ background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); overflow: hidden; }}
    .section-title {{ padding: 20px 24px; border-bottom: 1px solid #e2e8f0; font-weight: 700; font-size: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #f8fafc; padding: 12px 16px; text-align: left; font-size: 12px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #e2e8f0; }}
    td {{ padding: 12px 16px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover {{ background: #fafafa; }}
    .footer {{ text-align: center; padding: 24px; color: #94a3b8; font-size: 13px; }}
    @media (max-width: 768px) {{ .header {{ padding: 24px 20px; }} th, td {{ padding: 8px; }} }}
  </style>
</head>
<body>

<div class="header">
  <h1>🔒 Security Pipeline Report</h1>
  <p>Generated: {now} &nbsp;|&nbsp; {commit_info}</p>
  <div class="status-badge">{status_icon} Pipeline {status}</div>
</div>

<div class="container">

  <div class="cards">
    <div class="card">
      <div class="number" style="color:#3b82f6">{total}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card">
      <div class="number" style="color:#dc2626">{tp}</div>
      <div class="label">True Positives</div>
    </div>
    <div class="card">
      <div class="number" style="color:#16a34a">{fp}</div>
      <div class="label">False Positives</div>
    </div>
    <div class="card">
      <div class="number" style="color:#d97706">{nr}</div>
      <div class="label">Needs Review</div>
    </div>
    <div class="card">
      <div class="number" style="color:{status_color}">{blocking}</div>
      <div class="label">Blocking Issues</div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">🔍 Vulnerability Analysis Results</div>
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Type</th>
            <th>File</th>
            <th>Verdict</th>
            <th>Confidence</th>
            <th>Explanation</th>
          </tr>
        </thead>
        <tbody>
          {rows if rows else '<tr><td colspan="7" style="text-align:center;padding:32px;color:#94a3b8">No findings</td></tr>'}
        </tbody>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  DevSecOps Pipeline — Semgrep + Snyk + Gemini AI &nbsp;|&nbsp; Run ID: {run_id or "local"}
</div>

</body>
</html>"""


def main():
    report_path = sys.argv[1] if len(sys.argv) > 1 else "reports/ai-report.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "reports/index.html"
    commit_sha  = sys.argv[3] if len(sys.argv) > 3 else ""
    run_id      = sys.argv[4] if len(sys.argv) > 4 else ""

    try:
        with open(report_path) as f:
            report = json.load(f)
    except Exception as e:
        print(f"Error reading report: {e}")
        report = {"summary": {}, "results": []}

    html = generate_html(report, commit_sha, run_id)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Report generated: {output_path}")


if __name__ == "__main__":
    main()
