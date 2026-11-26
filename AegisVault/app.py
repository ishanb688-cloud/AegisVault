"""Fresh AegisVault application entry point."""
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path
from core.assessment import router as assessment_router

app = FastAPI(
    title="AegisVault",
    description="Offline password and credential security assessment for authorised lab data.",
    version="1.0.0",
)
app.include_router(assessment_router)

@app.get("/api/health")
def health():
    return {"status": "online", "product": "AegisVault", "version": app.version}

@app.get("/", include_in_schema=False)
def home():
    return FileResponse(Path(__file__).parent / "index.html")
