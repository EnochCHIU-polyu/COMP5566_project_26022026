from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_create_audit_returns_id() -> None:
    response = client.post(
        "/api/v1/audits",
        json={
            "contract_name": "SimpleRandom",
            "source_code": "pragma solidity ^0.8.0; contract C{}",
            "model": "deepseek-v3.2",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "audit_id" in data
    assert data["status"] == "queued"


def test_get_snapshot_not_found() -> None:
    response = client.get("/api/v1/audits/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404
