from __future__ import annotations

import logging
from typing import Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.audits import router as audits_router
from app.api.routes.benchmark import router as benchmark_router
from app.api.routes.vulnerabilities import router as vulnerabilities_router


if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

app = FastAPI(title="Smart Contract Audit API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(audits_router)
app.include_router(benchmark_router)
app.include_router(vulnerabilities_router)


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}
