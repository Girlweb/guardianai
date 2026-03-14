from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import os
from dotenv import load_dotenv
load_dotenv()
import time

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

@app.get("/")
def root():
    return {"service": "GuardianAI API", "version": "2.0", "status": "operational"}

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
        "risk_score": 22,
        "adjusted_risk_score": 29,
        "isolation_level": "MEDIUM",
        "findings": {
            "dependencies": {"findings_count": 6, "findings": []},
            "secrets": {"findings_count": 0, "findings": []}
        },
        "runtime_context": {
            "docker": {"has_dockerfile": True, "runs_as_root": False},
            "microsegmentation": {
                "isolation_score": 70,
                "isolation_level": "MEDIUM",
                "issues": ["No Kubernetes NetworkPolicy"],
                "risk_multiplier": 1.3
            }
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
    from scanner import logged_scan_v2

    start = time.time()

    results = await logged_scan_v2(
        repo_url=str(request.repo_url),
        branch=request.branch,
        user_id="api"
    )

    risk_score = results["summary"]["risk_score"]
    adjusted = results["summary"].get("adjusted_risk_score", risk_score)
    maturity_score = max(0, 100 - adjusted)

    if maturity_score >= 90: level = "Level 5: Optimized"
    elif maturity_score >= 75: level = "Level 4: Managed"
    elif maturity_score >= 60: level = "Level 3: Defined"
    elif maturity_score >= 40: level = "Level 2: Repeatable"
    else: level = "Level 1: Initial"

    ai = results.get("ai_analysis", {})

    return {
        "scan_id": results.get("scan_id"),
        "repo_url": str(request.repo_url),
        "status": "completed",
        "maturity_score": maturity_score,
        "maturity_level": level,
        "scan_time": round(time.time() - start, 2),
        "risk_score": risk_score,
        "adjusted_risk_score": adjusted,
        "isolation_level": results["summary"].get("isolation_level", "UNKNOWN"),
        "findings": results["scans"],
        "runtime_context": results.get("runtime_context", {}),
        "ai_summary": ai.get("summary", "Analysis complete"),
        "recommendations": ai.get("recommendations", [])
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
