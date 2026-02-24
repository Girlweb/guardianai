from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import os
from datetime import datetime

app = FastAPI(title="GuardianAI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    repo_url: HttpUrl
    branch: str = "main"
    scan_type: str = "quick"

class ScanResult(BaseModel):
    scan_id: str
    repo_url: str
    status: str
    maturity_score: int
    maturity_level: str
    scan_time: float
    findings: Dict[str, Any]
    ai_summary: str
    recommendations: List[str]

@app.get("/")
def root():
    return {"service": "GuardianAI API", "status": "operational"}

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "anthropic_api": "configured" if os.getenv("ANTHROPIC_API_KEY") else "missing"
    }

@app.get("/demo")
def demo_scan():
    return {
        "scan_id": "demo_123",
        "repo_url": "https://github.com/demo/project",
        "status": "completed",
        "maturity_score": 78,
        "maturity_level": "Level 4: Managed",
        "scan_time": 2.3,
        "findings": {
            "sast": [{"tool": "Semgrep", "status": "pass", "findings_count": 5}],
            "secrets": [{"tool": "TruffleHog", "status": "pass", "findings_count": 0}]
        },
        "ai_summary": "Repository shows strong security posture with minor gaps.",
        "recommendations": [
            "Enable artifact signing",
            "Add SBOM generation",
            "Implement automated dependency updates"
        ]
    }

@app.post("/scan")
async def scan_repository(request: ScanRequest):
    from scanner import SecurityScanner
    import time
    
    start = time.time()
    scanner = SecurityScanner()
    
    try:
        repo_path = scanner.clone_repo(str(request.repo_url), request.branch)
        results = scanner.scan_all(repo_path)
        repo_name = str(request.repo_url).split('/')[-1].replace('.git', '')
        ai_results = await scanner.ai_analyze(repo_name)
        
        score = max(0, 100 - results["summary"]["risk_score"])
        
        if score >= 90: level = "Level 5: Optimized"
        elif score >= 75: level = "Level 4: Managed"
        elif score >= 60: level = "Level 3: Defined"
        elif score >= 40: level = "Level 2: Repeatable"
        else: level = "Level 1: Initial"
        
        return ScanResult(
            scan_id=f"scan_{int(time.time())}",
            repo_url=str(request.repo_url),
            status="completed",
            maturity_score=score,
            maturity_level=level,
            scan_time=round(time.time() - start, 2),
            findings=results["scans"],
            ai_summary=ai_results.get("summary", "Analysis complete"),
            recommendations=ai_results.get("recommendations", [])
        )
    finally:
        scanner.cleanup()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
