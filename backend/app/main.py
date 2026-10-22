"""
NetSec Analyzer — Main FastAPI Application Entrypoint.
Configures CORS, API routes, database initialization, and local-first execution.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router as api_router

app = FastAPI(
    title="NetSec Analyzer API",
    description="Local-first network design security and attack-path analysis engine",
    version="1.0.0"
)

# Enable CORS for local development (Vite frontend on 5173, etc.)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")


@app.get("/")
def root():
    return {
        "app": "NetSec Analyzer",
        "description": "Scan network designs, reconstruct topologies, evaluate attack paths, and verify remediations.",
        "api_docs": "/docs",
        "health": "/api/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
