"""Canonical operation-to-tool mapping tests."""
import pytest

from app.scanners.operations import (normalize_tools, operation_tools,
                                     parameters_for_tool)


def test_technology_operations_allow_expected_fingerprint_sources():
    assert set(operation_tools("tech_detection")) == {"httpx", "webanalyze", "whatweb"}
    assert set(operation_tools("fingerprint_identification")) == {
        "httpx", "webanalyze", "whatweb", "nuclei"
    }


def test_normalize_tools_deduplicates_and_rejects_wrong_operation():
    assert normalize_tools("tech_detection", ["httpx", "whatweb", "httpx"]) == ["httpx", "whatweb"]
    with pytest.raises(ValueError, match="not allowed"):
        normalize_tools("tech_detection", ["nmap"])


def test_normalize_tools_rejects_nuclei_for_tech_detection():
    with pytest.raises(ValueError, match="not allowed"):
        normalize_tools("tech_detection", ["nuclei"])


def test_nuclei_technology_parameters_are_explicit():
    params = parameters_for_tool("fingerprint_identification", "nuclei", "http://example.com",
                                {"targets": ["http://example.com"]})
    assert params["mode"] == "technology"
    assert params["tags"] == ["tech"]
    assert params["targets"] == ["http://example.com"]


def test_domain_operations_keep_domain_parameter():
    params = parameters_for_tool("subdomain_discovery", "subfinder", "example.com", {})
    assert params == {"domain": "example.com"}


def test_webanalyze_and_whatweb_use_single_target_parameters():
    for tool in ("webanalyze", "whatweb"):
        params = parameters_for_tool("fingerprint_identification", tool,
                                     "http://example.com", {"targets": ["http://example.com"]})
        assert params == {"target": "http://example.com"}


def test_webanalyze_and_whatweb_keep_multiple_targets():
    for tool in ("webanalyze", "whatweb"):
        params = parameters_for_tool("fingerprint_identification", tool,
                                     ["http://one.example", "https://two.example"], {})
        assert params == {"targets": ["http://one.example", "https://two.example"]}


def test_httpx_keeps_all_requested_targets():
    params = parameters_for_tool("tech_detection", "httpx",
                                 ["http://one.example", "http://two.example"], {})
    assert params == {"targets": ["http://one.example", "http://two.example"]}
