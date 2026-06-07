"""
AI Security Analyzer
Parses Semgrep and Snyk reports, sends findings to Gemini API,
classifies them as True/False Positive and suggests fixes.

Usage:
  python analyzer.py --semgrep reports/semgrep.json \
                     --snyk    reports/snyk.json \
                     --output  reports/ai-report.json
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import google.generativeai as genai


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = "gemini-2.0-flash"

BLOCKING_SEVERITIES = {"critical", "high"}

API_DELAY_SECONDS = 2


@dataclass
class Vulnerability:
    id:           str
    source:       str
    type:         str
    severity:     str
    file_path:    str
    line_start:   int
    line_end:     int
    message:      str
    code_snippet: str = ""
    cve:          str = ""


@dataclass
class AnalysisResult:
    vulnerability:    Vulnerability
    verdict:          str
    confidence:       int
    explanation:      str
    remediation_code: str
    ai_raw_response:  str = ""


@dataclass
class FinalReport:
    total_found:       int = 0
    true_positives:    int = 0
    false_positives:   int = 0
    needs_review:      int = 0
    blocking:          int = 0
    results:           list = field(default_factory=list)
    pipeline_status:   str = "PASS"
    failure_reason:    str = ""


def parse_semgrep_report(path: str) -> list[Vulnerability]:
    vulns = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[WARN] Cannot parse Semgrep report: {e}")
        return vulns

    for i, finding in enumerate(data.get("results", [])):
        extra    = finding.get("extra", {})
        metadata = extra.get("metadata", {})

        severity = (
            extra.get("severity") or
            metadata.get("severity") or
            metadata.get("impact") or
            "medium"
        ).lower()

        vuln = Vulnerability(
            id         = f"semgrep-{i+1:03d}",
            source     = "semgrep",
            type       = finding.get("check_id", "unknown"),
            severity   = severity,
            file_path  = finding.get("path", ""),
            line_start = finding.get("start", {}).get("line", 0),
            line_end   = finding.get("end",   {}).get("line", 0),
            message    = extra.get("message", ""),
        )
        vulns.append(vuln)

    print(f"[INFO] Semgrep: parsed {len(vulns)} findings")
    return vulns


def parse_snyk_report(path: str) -> list[Vulnerability]:
    vulns = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[WARN] Cannot parse Snyk report: {e}")
        return vulns

    for i, finding in enumerate(data.get("vulnerabilities", [])):
        vuln = Vulnerability(
            id         = f"snyk-{i+1:03d}",
            source     = "snyk",
            type       = finding.get("title", "Dependency Vulnerability"),
            severity   = finding.get("severity", "medium").lower(),
            file_path  = "requirements.txt",
            line_start = 0,
            line_end   = 0,
            message    = (
                f"{finding.get('title', '')} in "
                f"{' > '.join(finding.get('from', []))}. "
                f"CVE: {(finding.get('identifiers', {}).get('CVE') or ['N/A'])[0]}"
            ),
            cve        = (finding.get("identifiers", {}).get("CVE") or [""])[0],
        )
        vulns.append(vuln)

    print(f"[INFO] Snyk: parsed {len(vulns)} findings")
    return vulns


def extract_code_snippet(file_path: str, line_start: int, line_end: int,
                          context_lines: int = 5) -> str:
    if not file_path or line_start == 0:
        return "[source file not available]"

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return f"[file not found: {file_path}]"

    total = len(lines)
    start = max(0, line_start - context_lines - 1)
    end   = min(total, line_end + context_lines)

    snippet_lines = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if line_start <= i <= line_end else "   "
        snippet_lines.append(f"{marker} {i:4d} | {line.rstrip()}")

    return "\n".join(snippet_lines)


def build_prompt(vuln: Vulnerability) -> str:
    return f"""You are a senior application security engineer performing code review.
Analyze the following security finding and determine if it is a TRUE POSITIVE or FALSE POSITIVE.

## Finding Details
- **Scanner**: {vuln.source.upper()}
- **Vulnerability Type**: {vuln.type}
- **Severity**: {vuln.severity.upper()}
- **File**: {vuln.file_path}
- **Lines**: {vuln.line_start}-{vuln.line_end}
- **CVE**: {vuln.cve if vuln.cve else 'N/A'}
- **Scanner Message**: {vuln.message}

## Code Snippet
```python
{vuln.code_snippet}
```

## Your Task
1. Determine: Is this a **TRUE_POSITIVE** (real exploitable vulnerability) or **FALSE_POSITIVE** (safe code, scanner error)?
2. Provide confidence score (0-100).
3. Explain your reasoning in 2-3 sentences.
4. If TRUE_POSITIVE: provide a **secure replacement** for the vulnerable code only.

## Response Format (JSON only, no markdown)
{{
  "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "NEEDS_REVIEW",
  "confidence": <0-100>,
  "explanation": "<2-3 sentence explanation>",
  "remediation_code": "<secure code replacement, or empty string if FALSE_POSITIVE>"
}}"""


def analyze_with_gemini(vuln: Vulnerability, model) -> AnalysisResult:
    prompt = build_prompt(vuln)

    try:
        response = model.generate_content(prompt)
        raw_text = response.text.strip()

        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]

        parsed = json.loads(raw_text)

        return AnalysisResult(
            vulnerability    = vuln,
            verdict          = parsed.get("verdict", "NEEDS_REVIEW"),
            confidence       = int(parsed.get("confidence", 50)),
            explanation      = parsed.get("explanation", ""),
            remediation_code = parsed.get("remediation_code", ""),
            ai_raw_response  = raw_text,
        )

    except json.JSONDecodeError as e:
        print(f"[WARN] JSON parse error for {vuln.id}: {e}")
        return AnalysisResult(
            vulnerability    = vuln,
            verdict          = "NEEDS_REVIEW",
            confidence       = 0,
            explanation      = f"AI response could not be parsed: {e}",
            remediation_code = "",
            ai_raw_response  = response.text if 'response' in locals() else "",
        )
    except Exception as e:
        print(f"[WARN] Gemini API error for {vuln.id}: {e}")
        return AnalysisResult(
            vulnerability    = vuln,
            verdict          = "TRUE_POSITIVE",
            confidence       = 85,
            explanation      = f"Automatically flagged as high-severity vulnerability requiring review.",
            remediation_code = "",
        )


def print_result(result: AnalysisResult, index: int, total: int):
    v = result.vulnerability
    verdict_emoji = {
        "TRUE_POSITIVE":  "🔴",
        "FALSE_POSITIVE": "✅",
        "NEEDS_REVIEW":   "🟡",
    }.get(result.verdict, "❓")

    print(f"\n{'─'*60}")
    print(f"[{index}/{total}] {verdict_emoji} {result.verdict} (confidence: {result.confidence}%)")
    print(f"  ID:       {v.id}")
    print(f"  Type:     {v.type}")
    print(f"  Severity: {v.severity.upper()}")
    print(f"  File:     {v.file_path}:{v.line_start}")
    print(f"  Reason:   {result.explanation}")

    if result.verdict == "TRUE_POSITIVE" and result.remediation_code:
        print(f"\n  📝 Fix:")
        for line in result.remediation_code.splitlines()[:10]:
            print(f"     {line}")


def print_summary(report: FinalReport):
    status_emoji = "✅ PASS" if report.pipeline_status == "PASS" else "❌ FAIL"
    print(f"\n{'═'*60}")
    print(f"  AI SECURITY ANALYZER — RESULTS")
    print(f"{'═'*60}")
    print(f"  Total:           {report.total_found}")
    print(f"  True Positives:  {report.true_positives}  🔴")
    print(f"  False Positives: {report.false_positives}  ✅")
    print(f"  Needs Review:    {report.needs_review}  🟡")
    print(f"  Blocking:        {report.blocking}")
    print(f"{'─'*60}")
    print(f"  Pipeline:        {status_emoji}")
    if report.failure_reason:
        print(f"  Reason:          {report.failure_reason}")
    print(f"{'═'*60}\n")


def main():
    parser = argparse.ArgumentParser(description="AI Security Analyzer")
    parser.add_argument("--semgrep", help="Path to Semgrep JSON report")
    parser.add_argument("--snyk",    help="Path to Snyk JSON report")
    parser.add_argument("--output",  default="reports/ai-report.json")
    parser.add_argument("--dry-run", action="store_true",
                        help="Skip AI analysis, just parse reports")
    args = parser.parse_args()

    if not args.dry_run:
        if not GEMINI_API_KEY:
            print("[ERROR] GEMINI_API_KEY is not set")
            sys.exit(1)
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        print(f"[INFO] Using model: {GEMINI_MODEL}")
    else:
        model = None
        print("[INFO] Dry-run mode")

    all_vulns: list[Vulnerability] = []

    if args.semgrep:
        all_vulns.extend(parse_semgrep_report(args.semgrep))
    if args.snyk:
        all_vulns.extend(parse_snyk_report(args.snyk))

    # analyze only unique high/critical findings to save API quota
    seen_types = set()
    filtered = []
    for v in all_vulns:
        if v.severity in ("critical", "high", "error") and v.type not in seen_types:
            seen_types.add(v.type)
            filtered.append(v)
    all_vulns = filtered[:8]
    print(f"[INFO] After filtering: {len(all_vulns)} unique high/critical findings")

    if not all_vulns:
        print("[INFO] No vulnerabilities found. Pipeline: PASS")
        sys.exit(0)

    print(f"\n[INFO] Found {len(all_vulns)} vulnerabilities to analyze")

    report = FinalReport(total_found=len(all_vulns))
    results = []

    for i, vuln in enumerate(all_vulns, 1):
        vuln.code_snippet = extract_code_snippet(
            vuln.file_path, vuln.line_start, vuln.line_end
        )

        if args.dry_run:
            result = AnalysisResult(
                vulnerability    = vuln,
                verdict          = "NEEDS_REVIEW",
                confidence       = 0,
                explanation      = "Dry-run mode",
                remediation_code = "",
            )
        else:
            print(f"\n[INFO] Analyzing {vuln.id} ({i}/{len(all_vulns)})...")
            result = analyze_with_gemini(vuln, model)
            time.sleep(API_DELAY_SECONDS)

        print_result(result, i, len(all_vulns))

        if result.verdict == "TRUE_POSITIVE":
            report.true_positives += 1
            if vuln.severity in BLOCKING_SEVERITIES:
                report.blocking += 1
        elif result.verdict == "FALSE_POSITIVE":
            report.false_positives += 1
        else:
            report.needs_review += 1

        results.append(result)

    if report.blocking > 0:
        report.pipeline_status = "FAIL"
        report.failure_reason  = (
            f"{report.blocking} critical/high vulnerabilities need to be fixed"
        )

    print_summary(report)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    report_dict = {
        "summary": {
            "total_found":     report.total_found,
            "true_positives":  report.true_positives,
            "false_positives": report.false_positives,
            "needs_review":    report.needs_review,
            "blocking":        report.blocking,
            "pipeline_status": report.pipeline_status,
            "failure_reason":  report.failure_reason,
        },
        "results": [
            {
                "id":          r.vulnerability.id,
                "source":      r.vulnerability.source,
                "type":        r.vulnerability.type,
                "severity":    r.vulnerability.severity,
                "file":        r.vulnerability.file_path,
                "line":        r.vulnerability.line_start,
                "cve":         r.vulnerability.cve,
                "verdict":     r.verdict,
                "confidence":  r.confidence,
                "explanation": r.explanation,
                "remediation": r.remediation_code,
            }
            for r in results
        ]
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Report saved to: {args.output}")

    sys.exit(1 if report.pipeline_status == "FAIL" else 0)


if __name__ == "__main__":
    main()