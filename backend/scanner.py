"""
GuardianAI Security Scanner - Version 2.0
Updated with expert feedback from Reddit r/cybersecurity

Improvements:
1. Production vs Staging environment detection
2. TruffleHog secret verification using built-in detectors
3. Public vs Internal endpoint detection (nginx/Terraform parsing)
4. Context-aware severity adjustment
5. Developer-friendly fix recommendations
"""

import subprocess
import json
import tempfile
import shutil
import os
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timezone
import re
from logging_system import GuardianAILoggingSystem

import git
import httpx
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class SecurityScanner:
    """Orchestrates multiple security scanning tools with context awareness"""

    def __init__(self, anthropic_api_key: Optional[str] = None):
        self.anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self.scan_results = {}
        self.repo_path = None
        self.environment = "UNKNOWN"
        self.public_endpoints = []

    def clone_repo(self, repo_url: str, branch: str = "main") -> str:
        """Clone a GitHub repository to temporary directory"""
        temp_dir = tempfile.mkdtemp(prefix="guardianai_")
        try:
            print(f" Cloning {repo_url} (branch: {branch})...")
            git.Repo.clone_from(repo_url, temp_dir, branch=branch, depth=1)
            self.repo_path = temp_dir
            
            # Detect environment context
            self.environment = self.detect_environment(temp_dir)
            self.public_endpoints = self.detect_public_endpoints(temp_dir)
            
            print(f" Environment detected: {self.environment}")
            if self.public_endpoints:
                print(f" Public endpoints found: {len(self.public_endpoints)}")
            
            return temp_dir
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"Failed to clone repository: {str(e)}")

    def detect_environment(self, repo_path: str) -> str:
        """
        Detect if code is production or staging
        Priority 1 improvement from French security expert feedback
        """
        # Method 1: Check branch name
        try:
            repo = git.Repo(repo_path)
            branch = repo.active_branch.name
            
            if branch in ['main', 'master', 'production', 'prod']:
                return 'PRODUCTION'
            elif branch in ['staging', 'stage', 'dev', 'development']:
                return 'STAGING'
        except:
            pass
        
        # Method 2: Check for environment files
        env_indicators = {
            'PRODUCTION': [
                '.env.production',
                '.env.prod',
                'config/production.yml',
                'production.env'
            ],
            'STAGING': [
                '.env.staging',
                '.env.stage',
                'config/staging.yml',
                'staging.env'
            ]
        }
        
        for env_type, files in env_indicators.items():
            for env_file in files:
                if os.path.exists(os.path.join(repo_path, env_file)):
                    return env_type
        
        return 'UNKNOWN'

    def detect_public_endpoints(self, repo_path: str) -> List[str]:
        """
        Find publicly exposed endpoints from nginx/Terraform configs
        Priority 2 improvement from French security expert feedback
        """
        public_endpoints = []
        
        # Check nginx configs
        nginx_patterns = ['*nginx.conf', '**/sites-enabled/*', '**/conf.d/*.conf']
        for pattern in nginx_patterns:
            for config_file in Path(repo_path).rglob(pattern):
                try:
                    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Look for public-facing server blocks
                        if 'listen 80' in content or 'listen 443' in content:
                            # Extract location blocks
                            locations = re.findall(r'location\s+([^\s{]+)', content)
                            public_endpoints.extend([f"nginx:{loc}" for loc in locations])
                except:
                    pass
        
        # Check Terraform for public ingress
        for tf_file in Path(repo_path).rglob('*.tf'):
            try:
                with open(tf_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Look for public CIDR blocks
                    if 'ingress' in content and '0.0.0.0/0' in content:
                        # Extract resource names
                        resources = re.findall(r'resource\s+"[^"]+"\s+"([^"]+)"', content)
                        public_endpoints.extend([f"terraform:{res}" for res in resources])
            except:
                pass
        
        return list(set(public_endpoints))

    def adjust_severity_by_context(self, finding: Dict) -> Dict:
        """
        Adjust severity based on environment and exposure context
        """
        original_severity = finding.get('severity', 'UNKNOWN')
        
        # Production environment increases severity
        if self.environment == 'PRODUCTION':
            if original_severity == 'HIGH':
                finding['severity'] = 'CRITICAL'
                finding['context_reason'] = 'PRODUCTION environment - immediate risk'
            elif original_severity == 'MEDIUM':
                finding['severity'] = 'HIGH'
                finding['context_reason'] = 'PRODUCTION environment - elevated priority'
        
        # Public exposure increases severity
        if finding.get('file') and any(endpoint in str(finding.get('file', '')) for endpoint in self.public_endpoints):
            current_severity = finding.get('severity', 'UNKNOWN')
            if current_severity == 'MEDIUM':
                finding['severity'] = 'HIGH'
                finding['context_reason'] = 'Publicly exposed endpoint - higher risk'
        
        return finding

    def scan_all(self, repo_path: str) -> Dict:
        """Run all security scans with context awareness"""
        self.repo_path = repo_path
        print(" Starting comprehensive security scan...\n")
        
        results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "repo_path": repo_path,
            "environment": self.environment,
            "public_endpoints_count": len(self.public_endpoints),
            "scans": {
                "sast": self.run_semgrep(),
                "secrets": self.run_trufflehog(),
                "dependencies": self.run_trivy(),
                "python_security": self.run_bandit(),
            },
            "summary": {}
        }
        
        # Calculate summary with context
        results["summary"] = self._calculate_summary(results["scans"])
        self.scan_results = results
        return results

    def run_semgrep(self) -> Dict:
        """Run Semgrep SAST analysis"""
        print(" → Running Semgrep (SAST)...")
        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config=auto",
                    "--json",
                    "--quiet",
                    self.repo_path
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            data = json.loads(result.stdout) if result.stdout else {}
            findings = data.get("results", [])
            
            # Apply context-aware severity adjustment
            processed_findings = []
            for f in findings[:20]:
                finding = {
                    "severity": f.get("extra", {}).get("severity", "unknown").upper(),
                    "message": f.get("extra", {}).get("message", ""),
                    "file": f.get("path", ""),
                    "line": f.get("start", {}).get("line", 0),
                    "rule_id": f.get("check_id", ""),
                }
                finding = self.adjust_severity_by_context(finding)
                processed_findings.append(finding)
            
            return {
                "tool": "semgrep",
                "status": "completed",
                "findings_count": len(findings),
                "findings": processed_findings
            }
        except subprocess.TimeoutExpired:
            return {"tool": "semgrep", "status": "timeout", "findings_count": 0, "findings": []}
        except Exception as e:
            return {"tool": "semgrep", "status": "error", "error": str(e), "findings_count": 0, "findings": []}

    def run_trufflehog(self) -> Dict:
        """
        Run TruffleHog with built-in secret verification
        Priority 3 improvement - uses TruffleHog's detectors to verify active secrets
        """
        print(" → Running TruffleHog (Secrets)...")
        try:
            result = subprocess.run(
                [
                    "trufflehog",
                    "filesystem",
                    self.repo_path,
                    "--json",
                    "--no-update"
                    # Note: --only-verified flag can be added to filter only verified secrets
                ],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            findings = []
            verified_count = 0
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        finding_data = json.loads(line)
                        
                        # TruffleHog v3 provides verification status
                        is_verified = finding_data.get("Verified", False)
                        if is_verified:
                            verified_count += 1
                        
                        finding = {
                            "type": finding_data.get("DetectorName", "unknown"),
                            "file": finding_data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", ""),
                            "verified": is_verified,
                            "severity": "CRITICAL" if is_verified else "MEDIUM",
                            "raw": finding_data.get("Raw", "")[:50] + "..." if finding_data.get("Raw") else "",
                            "verification_status": "ACTIVE" if is_verified else "UNKNOWN"
                        }
                        
                        # Apply context
                        finding = self.adjust_severity_by_context(finding)
                        findings.append(finding)
                        
                    except json.JSONDecodeError:
                        continue
            
            return {
                "tool": "trufflehog",
                "status": "completed",
                "findings_count": len(findings),
                "verified_secrets": verified_count,
                "findings": findings[:10]
            }
        except subprocess.TimeoutExpired:
            return {"tool": "trufflehog", "status": "timeout", "findings_count": 0, "verified_secrets": 0, "findings": []}
        except Exception as e:
            return {"tool": "trufflehog", "status": "error", "error": str(e), "findings_count": 0, "verified_secrets": 0, "findings": []}

    def run_trivy(self) -> Dict:
        """Run Trivy for dependencies and container scanning"""
        print(" → Running Trivy (Dependencies)...")
        try:
            result = subprocess.run(
                [
                    "trivy",
                    "fs",
                    "--format", "json",
                    "--quiet",
                    "--severity", "HIGH,CRITICAL",
                    self.repo_path
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            data = json.loads(result.stdout) if result.stdout else {}
            all_vulns = []
            
            for result_item in data.get("Results", []):
                for vuln in result_item.get("Vulnerabilities", []):
                    finding = {
                        "cve_id": vuln.get("VulnerabilityID", ""),
                        "package": vuln.get("PkgName", ""),
                        "version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "severity": vuln.get("Severity", ""),
                        "title": vuln.get("Title", "")
                    }
                    finding = self.adjust_severity_by_context(finding)
                    all_vulns.append(finding)
            
            return {
                "tool": "trivy",
                "status": "completed",
                "findings_count": len(all_vulns),
                "findings": all_vulns[:15]
            }
        except subprocess.TimeoutExpired:
            return {"tool": "trivy", "status": "timeout", "findings_count": 0, "findings": []}
        except Exception as e:
            return {"tool": "trivy", "status": "error", "error": str(e), "findings_count": 0, "findings": []}

    def run_bandit(self) -> Dict:
        """Run Bandit for Python security issues"""
        print(" → Running Bandit (Python)...")
        
        # Check if there are any Python files
        py_files = list(Path(self.repo_path).rglob("*.py"))
        if not py_files:
            return {
                "tool": "bandit",
                "status": "skipped",
                "reason": "No Python files found",
                "findings_count": 0,
                "findings": []
            }
        
        try:
            result = subprocess.run(
                [
                    "bandit",
                    "-r", self.repo_path,
                    "-f", "json",
                    "-ll"
                ],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            data = json.loads(result.stdout) if result.stdout else {}
            findings_data = data.get("results", [])
            
            processed_findings = []
            for f in findings_data[:10]:
                finding = {
                    "severity": f.get("issue_severity", ""),
                    "confidence": f.get("issue_confidence", ""),
                    "message": f.get("issue_text", ""),
                    "file": f.get("filename", ""),
                    "line": f.get("line_number", 0),
                    "test_id": f.get("test_id", "")
                }
                finding = self.adjust_severity_by_context(finding)
                processed_findings.append(finding)
            
            return {
                "tool": "bandit",
                "status": "completed",
                "findings_count": len(findings_data),
                "findings": processed_findings
            }
        except subprocess.TimeoutExpired:
            return {"tool": "bandit", "status": "timeout", "findings_count": 0, "findings": []}
        except Exception as e:
            return {"tool": "bandit", "status": "error", "error": str(e), "findings_count": 0, "findings": []}

    def _calculate_summary(self, scans: Dict) -> Dict:
        """Calculate overall summary statistics with context awareness"""
        total_findings = sum(
            scan.get("findings_count", 0) for scan in scans.values()
        )
        
        # Count by severity with context adjustments
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for scan in scans.values():
            for finding in scan.get("findings", []):
                severity = finding.get("severity", "").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Calculate risk score with environment multiplier
        base_risk = min(100, (
            severity_counts["CRITICAL"] * 20 +
            severity_counts["HIGH"] * 10 +
            severity_counts["MEDIUM"] * 5 +
            severity_counts["LOW"] * 2
        ))
        
        # Apply environment multiplier
        if self.environment == "PRODUCTION":
            risk_score = min(100, int(base_risk * 1.5))
        else:
            risk_score = base_risk
        
        return {
            "total_findings": total_findings,
            "by_severity": severity_counts,
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "environment": self.environment,
            "context_applied": True
        }

    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"

    async def ai_analyze(self, repo_name: str) -> Dict:
        """
        Send findings to Claude for AI analysis with developer-friendly recommendations
        Updated prompt based on French expert feedback: focus on actionable 3-step fixes
        """
        if not self.anthropic_api_key:
            return {
                "summary": "AI analysis unavailable (no API key configured)",
                "recommendations": ["Configure ANTHROPIC_API_KEY to enable AI-powered insights"],
                "fix_effort_hours": 0
            }
        
        if not self.scan_results:
            return {
                "summary": "No scan results available",
                "recommendations": ["Run security scan first"],
                "fix_effort_hours": 0
            }
        
        print(" Analyzing with Claude AI...")
        
        # Prepare context-rich prompt for developer-friendly fixes
        prompt = f"""You are a security engineer explaining findings to a developer who needs to fix them quickly.

Repository: {repo_name}
Environment: {self.environment}
Public endpoints: {len(self.public_endpoints)}

SCAN SUMMARY:
- Total findings: {self.scan_results['summary']['total_findings']}
- Critical: {self.scan_results['summary']['by_severity']['CRITICAL']}
- High: {self.scan_results['summary']['by_severity']['HIGH']}
- Risk Score: {self.scan_results['summary']['risk_score']}/100

TOP FINDINGS BY TOOL:
"""
        
        # Add sample findings from each tool
        for tool_name, tool_data in self.scan_results['scans'].items():
            if tool_data.get('findings'):
                prompt += f"\n{tool_name.upper()}:\n"
                for finding in tool_data['findings'][:3]:
                    prompt += f"  - {finding}\n"
        
        prompt += """

For the TOP 3 most critical findings, provide:

1. WHAT IT IS: Explain the vulnerability in simple terms (1 sentence)
2. THE RISK: "An attacker could [specific action]" (1 sentence)
3. THE FIX: Provide a 3-step fix with specific commands/actions:
   Step 1: [exact command or action]
   Step 2: [exact command or action]
   Step 3: [verification step]
4. PREVENTION: How to prevent this from happening again (1 sentence)

Format your response as JSON:
{
  "summary": "2-sentence executive summary of security posture",
  "recommendations": [
    "Fix 1: [What] - [Why] - [How in 3 steps]",
    "Fix 2: [What] - [Why] - [How in 3 steps]",
    "Fix 3: [What] - [Why] - [How in 3 steps]"
  ],
  "fix_effort_hours": estimated_hours_total,
  "priority_order": "1 (highest risk) to 3 (lower risk)"
}

Focus on actionable fixes developers can implement in the next 30 minutes, not just CVSS scores."""
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.anthropic_api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-sonnet-4-20250514",
                        "max_tokens": 1000,
                        "messages": [{"role": "user", "content": prompt}]
                    }
                )
                
                data = response.json()
                
                if response.status_code != 200:
                    print(f"API error: {data}")
                    return {
                        "summary": "API error occurred",
                        "recommendations": ["Check API key and credits"],
                        "fix_effort_hours": 0
                    }
                
                ai_text = data.get("content", [{}])[0].get("text", "")
                
                if not ai_text:
                    return {
                        "summary": "Empty API response",
                        "recommendations": ["Retry analysis"],
                        "fix_effort_hours": 0
                    }
                
                # Try to parse as JSON
                try:
                    # Remove markdown code blocks if present
                    ai_text = re.sub(r'```json\s*|\s*```', '', ai_text).strip()
                    return json.loads(ai_text)
                except json.JSONDecodeError:
                    # Fallback if not valid JSON
                    lines = [l.strip() for l in ai_text.strip().split('\n') if l.strip()]
                    return {
                        "summary": lines[0] if lines else "Analysis complete",
                        "recommendations": [l.strip('- ').strip() for l in lines[1:4] if l.strip()],
                        "fix_effort_hours": 4
                    }
                    
        except Exception as e:
            print(f"AI analysis error: {e}")
            return {
                "summary": "AI analysis failed",
                "recommendations": ["Check API configuration", "Verify credits available"],
                "fix_effort_hours": 0
            }

    def cleanup(self):
        """Clean up temporary files"""
        if self.repo_path and os.path.exists(self.repo_path):
            shutil.rmtree(self.repo_path, ignore_errors=True)


# Convenience function for quick scans
async def quick_scan(repo_url: str, branch: str = "main") -> Dict:
    """Run a complete security scan on a repository with context awareness"""
    scanner = SecurityScanner()
    try:
        # Clone repo (also detects environment and public endpoints)
        repo_path = scanner.clone_repo(repo_url, branch)
        
        # Run scans with context
        scan_results = scanner.scan_all(repo_path)
        
        # AI analysis with developer-friendly recommendations
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        ai_results = await scanner.ai_analyze(repo_name)
        
        # Combine results
        return {
            **scan_results,
            "ai_analysis": ai_results
        }
    finally:
        scanner.cleanup()


if __name__ == "__main__":
    # Test the scanner
    import asyncio
    
    async def test():
        print(" Testing GuardianAI Scanner v2.0\n")
        print("Features:")
        print("   Production vs Staging detection")
        print("   TruffleHog secret verification")
        print("   Public endpoint detection")
        print("   Context-aware severity adjustment")
        print("   Developer-friendly AI recommendations\n")
        
        # Test with a small public repo
        test_repo = "https://github.com/tiangolo/fastapi"
        
        results = await quick_scan(test_repo, branch="master")
        
        print("\n" + "="*50)
        print(" SCAN RESULTS")
        print("="*50)
        print(f"Environment: {results['environment']}")
        print(f"Public endpoints: {results.get('public_endpoints_count', 0)}")
        print(json.dumps(results["summary"], indent=2))
        
        print(f"\n AI Analysis: {results['ai_analysis']['summary']}")
        
        print("\n Top Recommendations:")
        for i, rec in enumerate(results['ai_analysis']['recommendations'][:3], 1):
            print(f"  {i}. {rec}")
        
        print(f"\n Estimated fix time: {results['ai_analysis'].get('fix_effort_hours', 'N/A')} hours")
    
    asyncio.run(test())


# ─── LOGGED SCAN (use this instead of quick_scan for production) ───────────────

async def logged_scan(repo_url: str, branch: str = "main", user_id: str = "system") -> Dict:
    """quick_scan with automatic SOC2-compliant logging"""
    from logging_system import GuardianAILoggingSystem
    import uuid

    logger = GuardianAILoggingSystem()
    scan_id = str(uuid.uuid4())

    results = await quick_scan(repo_url, branch)

    logger.log_scan_event(
        scan_id=scan_id,
        repo_url=repo_url,
        user_id=user_id,
        results=results
    )

    for tool_data in results.get("scans", {}).values():
        for finding in tool_data.get("findings", []):
            logger.log_finding_detected(finding, scan_id)

    results["scan_id"] = scan_id
    results["logged"] = True
    return results


async def logged_scan(repo_url: str, branch: str = "main", user_id: str = "system") -> Dict:
    """quick_scan with automatic SOC2-compliant logging"""
    from logging_system import GuardianAILoggingSystem
    import uuid

    logger = GuardianAILoggingSystem()
    scan_id = str(uuid.uuid4())

    results = await quick_scan(repo_url, branch)

    logger.log_scan_event(
        scan_id=scan_id,
        repo_url=repo_url,
        user_id=user_id,
        results=results
    )

    for tool_data in results.get("scans", {}).values():
        for finding in tool_data.get("findings", []):
            logger.log_finding_detected(finding, scan_id)

    results["scan_id"] = scan_id
    results["logged"] = True
    return results
