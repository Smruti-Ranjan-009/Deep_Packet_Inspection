"""
FastAPI wrapper around the dpi_engine C++ binary.

Accepts an uploaded .pcap, runs it through dpi_engine with optional
blocking rules, and returns the text report + a link to download the
filtered output pcap.
"""
import os
import shlex
import subprocess
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Path to the compiled binary. Overridable via env var so the same image
# works whether the build stage names it dpi_engine, dpi_engine.exe, etc.
DPI_ENGINE_BIN = os.environ.get("DPI_ENGINE_BIN", "/usr/local/bin/dpi_engine")

# Where uploaded/generated pcaps live. Ephemeral on Render's free tier —
# that's fine, each job gets its own subfolder and nothing needs to persist.
WORK_DIR = Path(os.environ.get("DPI_WORK_DIR", "/tmp/dpi_jobs"))
WORK_DIR.mkdir(parents=True, exist_ok=True)

# Hard cap so nobody can hang the box with an enormous capture.
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
SUBPROCESS_TIMEOUT_SECONDS = 60

app = FastAPI(
    title="DPI Engine API",
    description="Upload a pcap, get back classified/filtered traffic.",
    version="1.0.0",
)


class AnalyzeResponse(BaseModel):
    job_id: str
    report: str
    download_url: str


@app.get("/health")
def health():
    """Render/Docker healthcheck target. Also confirms the binary exists."""
    binary_ok = os.path.isfile(DPI_ENGINE_BIN) and os.access(DPI_ENGINE_BIN, os.X_OK)
    return {"status": "ok" if binary_ok else "degraded", "binary_found": binary_ok}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    file: UploadFile = File(..., description="Input .pcap file"),
    block_app: List[str] = Form(default=[], description="App name to block, repeatable"),
    block_ip: List[str] = Form(default=[], description="Source IP to block, repeatable"),
    block_domain: List[str] = Form(default=[], description="Domain substring to block, repeatable"),
    lbs: Optional[int] = Form(default=None, description="Load balancer thread count"),
    fps: Optional[int] = Form(default=None, description="Fast-path threads per LB"),
):
    if not file.filename.lower().endswith(".pcap"):
        raise HTTPException(400, "File must have a .pcap extension")

    job_id = uuid.uuid4().hex[:12]
    job_dir = WORK_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    input_path = job_dir / "input.pcap"
    output_path = job_dir / "output.pcap"

    # Stream to disk with a size cap instead of loading the whole upload
    # into memory.
    size = 0
    with open(input_path, "wb") as f:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                raise HTTPException(413, f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit")
            f.write(chunk)

    if size == 0:
        raise HTTPException(400, "Uploaded file is empty")

    cmd = [DPI_ENGINE_BIN, str(input_path), str(output_path)]
    # Swagger's "Try it out" UI can submit an empty string for a repeatable
    # form field that was left blank, rather than omitting it entirely.
    # An empty --block-domain value matches every SNI in the engine's rule
    # logic (empty-string substring search always "matches"), silently
    # dropping all traffic -- so filter blanks out here defensively, in
    # addition to the engine now also rejecting them itself.
    for app_name in (a.strip() for a in block_app if a and a.strip()):
        cmd += ["--block-app", app_name]
    for ip in (i.strip() for i in block_ip if i and i.strip()):
        cmd += ["--block-ip", ip]
    for domain in (d.strip() for d in block_domain if d and d.strip()):
        cmd += ["--block-domain", domain]
    if lbs:
        cmd += ["--lbs", str(lbs)]
    if fps:
        cmd += ["--fps", str(fps)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "dpi_engine timed out processing this capture")
    except FileNotFoundError:
        raise HTTPException(500, f"dpi_engine binary not found at {DPI_ENGINE_BIN}")

    if result.returncode != 0:
        raise HTTPException(
            422,
            f"dpi_engine failed (exit {result.returncode}): {result.stderr.strip() or result.stdout.strip()}",
        )

    if not output_path.exists():
        raise HTTPException(500, "dpi_engine reported success but produced no output file")

    return AnalyzeResponse(
        job_id=job_id,
        report=result.stdout,
        download_url=f"/download/{job_id}",
    )


@app.get("/download/{job_id}")
def download(job_id: str):
    # job_id comes from uuid4().hex, but validate anyway before touching the filesystem.
    if not job_id.isalnum():
        raise HTTPException(400, "Invalid job id")

    output_path = WORK_DIR / job_id / "output.pcap"
    if not output_path.exists():
        raise HTTPException(404, "Job not found or output not generated")

    return FileResponse(
        output_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{job_id}_filtered.pcap",
    )
