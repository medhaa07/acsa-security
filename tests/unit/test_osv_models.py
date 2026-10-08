"""Unit tests for OSV request schemas, response parsing, and vulnerability normalization."""

from acsa.vulnerability.osv_models import (
    OSVBatchQuery,
    OSVPackage,
    OSVQuery,
    normalize_osv_advisory,
)


def test_osv_request_construction() -> None:
    """Verify construction of single and batch OSV query payloads."""
    pkg = OSVPackage(name="lodash", ecosystem="npm")
    query = OSVQuery(package=pkg, version="4.17.20")
    batch = OSVBatchQuery(queries=[query])

    assert query.package.name == "lodash"
    assert query.package.ecosystem == "npm"
    assert query.version == "4.17.20"
    assert len(batch.queries) == 1
    assert batch.queries[0].package.name == "lodash"


def test_npm_ecosystem_normalization() -> None:
    """Verify npm ecosystem defaulting and preservation."""
    pkg_default = OSVPackage(name="cookie")
    assert pkg_default.ecosystem == "npm"

    pkg_explicit = OSVPackage(name="express", ecosystem="npm")
    assert pkg_explicit.ecosystem == "npm"


def test_osv_advisory_normalization_full() -> None:
    """Verify normalization of a full OSV payload with aliases, severity, ranges, and fixes."""
    payload = {
        "id": "GHSA-35jh-r3h4-6jhm",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "details": "All versions of package lodash prior to 4.17.21 are vulnerable.",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"},
                        ],
                    }
                ],
                "ecosystem_specific": {
                    "affected_functions": ["template"],
                },
            }
        ],
        "database_specific": {
            "severity": "HIGH",
        },
    }

    vuln = normalize_osv_advisory(payload)

    assert vuln.id == "GHSA-35jh-r3h4-6jhm"
    assert "CVE-2021-23337" in vuln.aliases
    assert vuln.summary == "Command Injection in lodash"
    assert vuln.details is not None
    assert vuln.severity == "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    assert "4.17.21" in vuln.fixed_versions
    assert ">=0 <4.17.21" in vuln.affected_ranges
    assert "template" in vuln.vulnerable_symbols
    assert vuln.database_specific.get("severity") == "HIGH"


def test_osv_advisory_normalization_minimal() -> None:
    """Verify safe fallback behavior for minimal or sparse OSV payloads."""
    payload = {
        "id": "CVE-2024-12345",
    }
    vuln = normalize_osv_advisory(payload)
    assert vuln.id == "CVE-2024-12345"
    assert "CVE-2024-12345" in vuln.summary
    assert vuln.aliases == []
    assert vuln.fixed_versions == []
    assert vuln.affected_ranges == []
