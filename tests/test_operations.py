"""Canonical operation-to-tool mapping tests."""
import pytest

from app.scanners.operations import (normalize_tools, operation_tools,
                                     parameters_for_tool)


def test_technology_operation_allows_expected_tools():
    assert set(operation_tools("tech_detection")) == {"httpx", "webanalyze", "whatweb"}


def test_normalize_tools_deduplicates_and_rejects_wrong_operation():
    assert normalize_tools("tech_detection", ["httpx", "whatweb", "httpx"]) == ["httpx", "whatweb"]
    with pytest.raises(ValueError, match="not allowed"):
        normalize_tools("tech_detection", ["nmap"])


def test_normalize_tools_rejects_nuclei_for_tech_detection():
    with pytest.raises(ValueError, match="not allowed"):
        normalize_tools("tech_detection", ["nuclei"])


def test_domain_operations_keep_domain_parameter():
    params = parameters_for_tool("subdomain_discovery", "subfinder", "example.com", {})
    assert params == {"domain": "example.com"}


def test_webanalyze_and_whatweb_use_single_target_parameters():
    for tool in ("webanalyze", "whatweb"):
        params = parameters_for_tool("tech_detection", tool,
                                     "http://example.com", {"targets": ["http://example.com"]})
        assert params == {"target": "http://example.com"}


def test_webanalyze_and_whatweb_keep_multiple_targets():
    for tool in ("webanalyze", "whatweb"):
        params = parameters_for_tool("tech_detection", tool,
                                     ["http://one.example", "https://two.example"], {})
        assert params == {"targets": ["http://one.example", "https://two.example"]}


def test_httpx_keeps_all_requested_targets():
    params = parameters_for_tool("tech_detection", "httpx",
                                 ["http://one.example", "http://two.example"], {})
    assert params == {"targets": ["http://one.example", "http://two.example"]}
