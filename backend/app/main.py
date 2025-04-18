from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import subprocess
import requests
import json
from pathlib import Path
import os
import platform
from google.cloud import vision

LOG_FILE_PATH = Path("activity_logs.jsonl")

def append_log(entry: dict):
    """Append a JSON log entry to the log file."""
    with open(LOG_FILE_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")

def read_logs():
    """Read all log entries from the log file."""
    logs = []
    if LOG_FILE_PATH.exists():
        with open(LOG_FILE_PATH, "r") as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # skip bad lines
    return logs

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Insecure wildcard for MVP testing — lock down in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Placeholder for blocked sites (will later connect to Squid Proxy)
blocked_sites = {"malicious.com", "phishing.com"}

# ✅ 1. API Endpoint to Add a Site to the Blocklist
class BlockRequest(BaseModel):
    domain: str

@app.post("/blocklist")
def block_site(request: BlockRequest):
    """Adds a domain to the blocklist and updates Squid Proxy dynamically."""
    blocked_sites.add(request.domain)

    # Append to blocklist file
    try:
        with open("/Users/mohammedsaibu/Custex-MVP/backend/proxy/etc/squid/blocked_sites.txt", "a") as f:
            f.write(request.domain + "\n")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update blocklist: {str(e)}")

    # ✅ Restart Squid Proxy properly based on OS
    restart_squid_proxy()
    append_log({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": f"Blocked domain: {request.domain}"
    })
    return {"message": f"Blocked {request.domain}"}

# ✅ 2. API Endpoint to Remove a Site from the Blocklist
@app.delete("/unblock/{domain}")
def unblock_site(domain: str):
    """Removes a domain from the blocklist and updates Squid."""
    if domain not in blocked_sites:
        raise HTTPException(status_code=404, detail="Domain not found in blocklist")

    blocked_sites.remove(domain)

    # ✅ Reload Squid's configuration dynamically
    restart_squid_proxy()

    append_log({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": f"Unblocked domain: {domain}"
    })

    return {"message": f"Unblocked {domain}"}

# ✅ 3. API Endpoint to List Blocked Sites
@app.get("/list-blocked-sites")
def list_blocked_sites():
    """Returns a list of blocked domains."""
    return {"blocked_sites": list(blocked_sites)}

# ✅ 4. Check Squid Proxy Status (Works on Both macOS & Linux)
def check_squid_status():
    """Check Squid Proxy status depending on OS."""
    try:
        if platform.system() == "Linux":
            result = subprocess.run(["systemctl", "is-active", "squid"], capture_output=True, text=True)
            status = result.stdout.strip()
        elif platform.system() == "Darwin":  # macOS
            result = subprocess.run(["brew", "services", "list"], capture_output=True, text=True)
            status = "active" if "squid" in result.stdout and "started" in result.stdout else "inactive"
        else:
            return {"error": "Unsupported OS"}

        return {"proxy_status": status}
    except Exception as e:
        return {"error": str(e)}

@app.get("/proxy-status")
def proxy_status():
    return check_squid_status()

# ✅ Helper Function to Restart Squid Proxy Correctly on macOS/Linux
def restart_squid_proxy():
    """Restarts Squid Proxy based on OS."""
    try:
        if platform.system() == "Linux":
            subprocess.run(["sudo", "systemctl", "restart", "squid"], check=True)
        elif platform.system() == "Darwin":
            subprocess.run(["brew", "services", "restart", "squid"], check=True)
        else:
            raise Exception("Unsupported OS")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restart Squid Proxy: {str(e)}")

# ✅ 5. Analyze Text Using Perspective API
class TextAnalysisRequest(BaseModel):
    text: str

PERSPECTIVE_API_KEY = os.getenv("PERSPECTIVE_API_KEY")

@app.post("/analyze-text")
def analyze_text(request: TextAnalysisRequest):
    """Analyzes text for harmful content using Perspective API."""
    url = "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze"
    headers = {"Content-Type": "application/json"}

    data = {
        "comment": {"text": request.text},
        "languages": ["en"],
        "requestedAttributes": {"TOXICITY": {}}
    }

    response = requests.post(url, json=data, params={"key": PERSPECTIVE_API_KEY}, headers=headers)

    if response.status_code == 200:
        full_result = response.json()
        score = full_result.get("attributeScores", {}).get("TOXICITY", {}).get("summaryScore", {}).get("value", "N/A")

        append_log({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": "Analyzed text",
            "input_text": request.text,
            "toxicity_score": round(score, 3) if isinstance(score, float) else score
        })

        return full_result

    else:
        raise HTTPException(status_code=response.status_code, detail=response.text)

# ✅ 6. Analyze an Image Using Google Vision API
# Initialize Vision API client
client = vision.ImageAnnotatorClient()

@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    """Analyzes uploaded image using Google Vision SafeSearch API."""
    try:
        contents = await file.read()
        image = vision.Image(content=contents)
        response = client.safe_search_detection(image=image)

        safe_search = response.safe_search_annotation

        # Format result for log & return
        result = {
            "adult": safe_search.adult,
            "violence": safe_search.violence,
            "racy": safe_search.racy,
            "medical": safe_search.medical,
            "spoof": safe_search.spoof
        }

        # Append to in-memory logs
        append_log({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event": f"Analyzed image: {file.filename}",
            "result": result
        })

        return {"file": file.filename, "result": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ✅ 7. Retrieve Recent Activity Logs
@app.get("/logs")
def get_logs():
    """Returns recent activity logs including moderation actions."""
    return {"logs": read_logs()}

# ✅ 8. Reload Squid Proxy Configuration
@app.post("/update-proxy-config")
def update_proxy_config():
    """Reloads Squid Proxy settings dynamically."""
    restart_squid_proxy()
    return {"message": "Squid Proxy configuration updated"}
