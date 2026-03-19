"""
GuardianAI Auto-Remediation Engine
Generates specific fix code for each vulnerability found
"""
import json
import httpx
import os
from typing import Dict, List
from dotenv import load_dotenv

load_dotenv()


async def generate_fix(finding: Dict, repo_context: Dict = {}) -> Dict:
    """Generate specific fix code for a vulnerability"""

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return _fallback_fix(finding)

    vuln_type = _detect_vuln_type(finding)
    prompt = _build_prompt(finding, vuln_type, repo_context)

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-6",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )

        if response.status_code != 200:
            return _fallback_fix(finding)

        data = response.json()
        ai_text = data.get("content", [{}])[0].get("text", "")

        try:
            return json.loads(ai_text)
        except:
            return {
                "fix_type": vuln_type,
                "description": ai_text[:200],
                "fix_code": ai_text,
                "effort_minutes": 10,
                "confidence": "medium"
            }

    except Exception as e:
        return _fallback_fix(finding)


def _detect_vuln_type(finding: Dict) -> str:
    """Detect what type of vulnerability this is"""
    if finding.get("cve_id"):
        return "dependency"
    if finding.get("type") in ["AWS", "GitHub", "Slack", "Google"]:
        return "secret"
    severity = (finding.get("severity") or "").lower()
    msg = (finding.get("message") or finding.get("title") or "").lower()
    if "sql" in msg:
        return "sql_injection"
    if "secret" in msg or "password" in msg or "key" in msg:
        return "hardcoded_secret"
    if "xss" in msg or "cross-site" in msg:
        return "xss"
    return "general"


def _build_prompt(finding: Dict, vuln_type: str, repo_context: Dict) -> str:
    """Build a targeted prompt based on vulnerability type"""

    base = f"""You are a security engineer. Generate a specific fix for this vulnerability.

VULNERABILITY:
Type: {vuln_type}
Severity: {finding.get('severity', 'HIGH')}
"""
    if vuln_type == "dependency":
        base += f"""Package: {finding.get('package', 'unknown')}
Current version: {finding.get('version', 'unknown')}
Fixed version: {finding.get('fixed_version', 'latest')}
CVE: {finding.get('cve_id', 'N/A')}
Title: {finding.get('title', '')[:100]}

Generate a fix in this exact JSON format:
{{
  "fix_type": "dependency_update",
  "description": "One sentence explaining the risk",
  "fix_code": "npm install package@fixed_version OR pip install package==fixed_version",
  "verification": "Command to verify fix worked",
  "effort_minutes": 5,
  "confidence": "high",
  "attack_scenario": "One sentence: attacker could..."
}}"""

    elif vuln_type == "secret":
        base += f"""Secret type: {finding.get('type', 'unknown')}
File: {finding.get('file', 'unknown')}

Generate a fix in this exact JSON format:
{{
  "fix_type": "secret_rotation",
  "description": "One sentence explaining the risk",
  "fix_code": "Step 1: Revoke key\\nStep 2: Generate new key\\nStep 3: Update environment variables",
  "verification": "Command to verify no secrets in code",
  "effort_minutes": 15,
  "confidence": "high",
  "attack_scenario": "One sentence: attacker could..."
}}"""

    else:
        base += f"""Message: {finding.get('message', finding.get('title', ''))[:150]}
File: {finding.get('file', 'unknown')}
Line: {finding.get('line', 'unknown')}

Generate a fix in this exact JSON format:
{{
  "fix_type": "code_fix",
  "description": "One sentence explaining the risk",
  "fix_code": "Specific code change needed",
  "verification": "How to verify fix",
  "effort_minutes": 30,
  "confidence": "medium",
  "attack_scenario": "One sentence: attacker could..."
}}"""

    base += "\n\nRespond with ONLY the JSON, no other text."
    return base


def _fallback_fix(finding: Dict) -> Dict:
    """Rule-based fallback when AI is unavailable"""

    vuln_type = _detect_vuln_type(finding)

    if vuln_type == "dependency":
        pkg = finding.get("package", "package")
        fixed = finding.get("fixed_version", "latest")
        return {
            "fix_type": "dependency_update",
            "description": f"Update {pkg} to fix {finding.get('cve_id', 'vulnerability')}",
            "fix_code": f"npm install {pkg}@{fixed}\n# or if using yarn:\nyarn add {pkg}@{fixed}\n# or pip:\npip install {pkg}=={fixed}",
            "verification": f"npm audit | grep {pkg}",
            "effort_minutes": 5,
            "confidence": "high",
            "attack_scenario": f"Attacker could exploit {finding.get('cve_id', 'this CVE')} to compromise your application",
            "ai_powered": False
        }

    elif vuln_type == "secret":
        return {
            "fix_type": "secret_rotation",
            "description": "Exposed secret detected - rotate immediately",
            "fix_code": "1. Revoke the exposed credential immediately\n2. Generate a new credential\n3. Store in environment variable or secrets manager\n4. Never commit secrets to git\n5. Add to .gitignore: .env, *.key, secrets.yml",
            "verification": "trufflehog filesystem . --only-verified",
            "effort_minutes": 15,
            "confidence": "high",
            "attack_scenario": "Attacker could use this credential to access your systems immediately",
            "ai_powered": False
        }

    else:
        return {
            "fix_type": "manual_review",
            "description": finding.get("message", "Security issue requires manual review")[:100],
            "fix_code": "Review flagged code and apply security best practices",
            "verification": "Re-run security scan after fix",
            "effort_minutes": 30,
            "confidence": "medium",
            "attack_scenario": "Attacker could exploit this vulnerability to compromise your application",
            "ai_powered": False
        }


async def remediate_scan(scan_results: Dict) -> Dict:
    """Generate fixes for all findings in a scan"""

    all_fixes = []
    total_effort = 0

    for tool_name, tool_data in scan_results.get("scans", {}).items():
        for finding in tool_data.get("findings", []):
            fix = await generate_fix(finding)
            fix["original_finding"] = {
                "tool": tool_name,
                "severity": finding.get("severity"),
                "package": finding.get("package"),
                "cve_id": finding.get("cve_id"),
                "file": finding.get("file", "")
            }
            all_fixes.append(fix)
            total_effort += fix.get("effort_minutes", 10)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_fixes.sort(key=lambda x: severity_order.get(
        x["original_finding"].get("severity", "LOW"), 4))

    return {
        "total_fixes": len(all_fixes),
        "total_effort_minutes": total_effort,
        "total_effort_hours": round(total_effort / 60, 1),
        "fixes": all_fixes,
        "priority_fix": all_fixes[0] if all_fixes else None
    }
