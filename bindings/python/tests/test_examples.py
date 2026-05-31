"""Routing contracts for the LangGraph gate example. No binary or
LangGraph needed — the decision logic is plain Python."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

import langgraph_gate as gate  # noqa: E402


def test_route_selects_node_by_verdict():
    assert gate.route_on_verdict({"verdict": "benign"}) == "benign"
    assert gate.route_on_verdict({"verdict": "suspicious"}) == "suspicious"
    assert gate.route_on_verdict({"verdict": "malicious"}) == "malicious"


def test_route_defaults_to_benign_when_absent():
    assert gate.route_on_verdict({}) == "benign"


def test_block_node_reports_block_and_lists_rule_ids():
    out = gate.block_node({"findings": [{"rule_id": "OFFICIAL_REMOTE_FETCH_EXEC"}]})
    assert out["decision"] == "block"
    assert "OFFICIAL_REMOTE_FETCH_EXEC" in out["reasons"][0]


def test_review_node_reports_review():
    out = gate.review_node({"findings": []})
    assert out["decision"] == "review"


def test_allow_node_reports_allow():
    out = gate.allow_node({})
    assert out["decision"] == "allow"
