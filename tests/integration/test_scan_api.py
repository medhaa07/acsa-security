"""Integration tests for the /scan and /api/v1/scan REST API endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from acsa.api.app import app
from acsa.inventory.models import CanonicalInventory, Component
from acsa.vulnerability.models import VulnerabilityScanResult

client = TestClient(app)


def test_api_scan_endpoint_success() -> None:
    """POST /api/v1/scan returns HTTP 200 and structured VulnerabilityScanResult schema."""
    sample_result = VulnerabilityScanResult(
        repository_path="tests/fixtures/repo_basic",
        inventory=CanonicalInventory(
            observations=[],
            components=[Component(name="cookie", version="0.6.0")],
            dependencies=[],
        ),
        findings=[],
        vulnerabilities=[],
        evidence=[],
        queries_executed=1,
        exact_versions_queried=1,
        advisories_count=0,
        affected_count=0,
        not_affected_count=0,
        unknown_count=0,
        osv_available=True,
        errors=[],
    )

    with patch(
        "acsa.vulnerability.service.VulnerabilityService.scan_inventory",
        return_value=sample_result,
    ):
        response = client.post(
            "/api/v1/scan",
            json={"repository_path": "tests/fixtures/repo_basic"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "inventory" in data
        assert data["exact_versions_queried"] == 1
        assert data["osv_available"] is True


def test_api_scan_root_endpoint_success() -> None:
    """POST /scan at root also returns HTTP 200."""
    sample_result = VulnerabilityScanResult(
        repository_path="tests/fixtures/repo_basic",
        inventory=CanonicalInventory(observations=[], components=[], dependencies=[]),
        findings=[],
        vulnerabilities=[],
        evidence=[],
        queries_executed=0,
        exact_versions_queried=0,
        advisories_count=0,
        affected_count=0,
        not_affected_count=0,
        unknown_count=0,
        osv_available=True,
        errors=[],
    )

    with patch(
        "acsa.vulnerability.service.VulnerabilityService.scan_inventory",
        return_value=sample_result,
    ):
        response = client.post(
            "/scan",
            json={"repository_path": "tests/fixtures/repo_basic"},
        )
        assert response.status_code == 200


def test_api_scan_path_traversal_blocked() -> None:
    """Dangerous path traversal attempts are blocked with HTTP 400."""
    response = client.post(
        "/api/v1/scan",
        json={"repository_path": "valid_path\x00_inject"},
    )
    assert response.status_code == 400
    assert "security violation" in response.json()["detail"].lower()


def test_api_scan_not_found() -> None:
    """Non-existent repository workspace paths return HTTP 404."""
    response = client.post(
        "/api/v1/scan",
        json={"repository_path": "tests/fixtures/does_not_exist_xyz"},
    )
    assert response.status_code == 404
