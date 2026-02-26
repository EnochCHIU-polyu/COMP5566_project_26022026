"""
Phase 4 – Evaluation: Audit report generator.

Generates markdown and HTML audit reports from experiment results.
"""

from __future__ import annotations
import os
import json
from datetime import datetime, timezone
from typing import Optional


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"
}


def generate_markdown_report(
    audit_result: dict,
    contract_name: str,
    model: str = "",
    temperature: float = 0.0,
    mode: str = "",
    include_appendix: bool = False,
) -> str:
    """
    Generate a markdown audit report from an audit result dict.

    Parameters
    ----------
    audit_result : dict
        Output from analyze_contract().
    contract_name : str
        Name of the audited contract.
    model : str
        LLM model used.
    temperature : float
        Temperature used.
    mode : str
        Classification mode used.
    include_appendix : bool
        If True, include full LLM responses in appendix.

    Returns
    -------
    str
        Markdown-formatted report.
    """
    vuln_results = audit_result.get("vuln_results", [])

    findings = []
    for vr in vuln_results:
        response = vr.get("response", "")
        vuln_name = vr.get("vuln_name", "")
        is_vuln = response.strip().upper().startswith("YES") or "YES" in response[:20].upper()
        if is_vuln:
            findings.append({
                "vuln_type": vuln_name,
                "severity": "HIGH",
                "description": response[:200].strip(),
                "lines": [],
                "recommendation": "Review and fix the identified vulnerability.",
            })

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Smart Contract Security Audit Report",
        "",
        f"**Contract:** {contract_name}  ",
        f"**Date:** {now}  ",
        f"**Model:** {model}  ",
        f"**Mode:** {mode}  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"This audit identified **{len(findings)}** security finding(s) in `{contract_name}`.",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 CRITICAL | {critical_count} |",
        f"| 🟠 HIGH | {high_count} |",
        f"| Total | {len(findings)} |",
        "",
        "---",
        "",
        "## 2. Findings",
        "",
    ]

    if findings:
        severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        findings.sort(key=lambda f: severity_rank.get(f.get("severity", "INFO"), 99))

        for i, finding in enumerate(findings, 1):
            sev = finding.get("severity", "MEDIUM")
            emoji = SEVERITY_EMOJI.get(sev, "⚪")
            vuln_type = finding.get("vuln_type", "Unknown")
            desc = finding.get("description", "")
            rec = finding.get("recommendation", "")
            lines_list = finding.get("lines", [])
            lines_str = ", ".join(f"L{ln}" for ln in lines_list) if lines_list else "Not specified"

            lines.extend([
                f"### Finding {i}: {vuln_type}",
                "",
                f"**Severity:** {emoji} {sev}  ",
                f"**Affected Lines:** {lines_str}  ",
                "",
                f"**Description:** {desc}",
                "",
                f"**Recommendation:** {rec}",
                "",
                "---",
                "",
            ])
    else:
        lines.extend([
            "No vulnerabilities detected.",
            "",
            "---",
            "",
        ])

    lines.extend([
        "## 3. Methodology",
        "",
        f"- **Model:** {model}",
        f"- **Temperature:** {temperature}",
        f"- **Mode:** {mode}",
        f"- **Vulnerability types checked:** {len(vuln_results)}",
        "",
    ])

    if include_appendix and vuln_results:
        lines.extend([
            "---",
            "",
            "## Appendix: Full LLM Responses",
            "",
        ])
        for vr in vuln_results:
            lines.extend([
                f"### {vr.get('vuln_name', 'Unknown')}",
                "",
                "```",
                vr.get("response", ""),
                "```",
                "",
            ])

    return "\n".join(lines)


def generate_html_report(
    audit_result: dict,
    contract_name: str,
    **kwargs,
) -> str:
    """Generate HTML report from audit result."""
    md_content = generate_markdown_report(audit_result, contract_name, **kwargs)
    escaped = md_content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Audit Report: {contract_name}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 2em; }}
        pre {{ background: #f5f5f5; padding: 1em; border-radius: 4px; overflow-x: auto; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #e64a19; }}
        .medium {{ color: #f57f17; }}
    </style>
</head>
<body>
<pre>{escaped}</pre>
</body>
</html>"""


def save_report(
    audit_result: dict,
    contract_name: str,
    output_path: str,
    format: str = "markdown",
    **kwargs,
) -> None:
    """Save audit report to file."""
    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)

    if format == "html":
        content = generate_html_report(audit_result, contract_name, **kwargs)
    else:
        content = generate_markdown_report(audit_result, contract_name, **kwargs)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
