"""Deterministic tests for the `json_parse` / `schema_validation` pipeline
stages (see app/core/sdk_core.py), exercised directly against
`parse_json_with_fallback()` and `LLMAction` — bypassing the LLM entirely.

Companion to the best-effort `malformed_payload` category in
redteam/attack_prompts.json: prompting Ollama to emit genuinely malformed
or non-JSON output is unreliable in BOTH pipelines, since both call it with
`format="json"` (see app/llm/ollama_client.py), which constrains the model's
output to syntactically valid JSON at the grammar level. These tests instead
feed hand-crafted strings straight into the same two functions the secure
pipeline actually calls, so INVALID_INPUT/unparseable-output handling is
verified deterministically, independent of what any given LLM happens to
produce on a given run.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.schemas import LLMAction
from app.core.sdk_core import parse_json_with_fallback


class TestParseJsonWithFallback:
    def test_none_input_returns_none(self):
        assert parse_json_with_fallback(None) is None

    def test_empty_string_returns_none(self):
        assert parse_json_with_fallback("") is None

    def test_plain_valid_json_object(self):
        result = parse_json_with_fallback('{"action": "get_status", "params": {}}')
        assert result == {"action": "get_status", "params": {}}

    def test_json_embedded_in_prose_uses_fallback_extraction(self):
        text = 'Sure, here is the action: {"action": "set_lights", "params": {"light": "headlights", "state": true}} hope that helps!'
        result = parse_json_with_fallback(text)
        assert result == {
            "action": "set_lights",
            "params": {"light": "headlights", "state": True},
        }

    def test_pure_prose_with_no_json_object_returns_none(self):
        assert parse_json_with_fallback("I cannot help with that request.") is None

    def test_truncated_json_missing_closing_brace_returns_none(self):
        # No balanced {...} block exists anywhere in the text, so the
        # fallback extractor can never find a candidate to re-parse.
        assert parse_json_with_fallback('{"action": "set_climate", "params": {"power": true') is None

    def test_unquoted_keys_non_json_returns_none(self):
        # Valid-looking but not valid JSON (bare/unquoted keys) — neither
        # json.loads() nor the fallback's re-parse of the extracted braces
        # can accept this.
        assert parse_json_with_fallback("{action: set_lights, params: {light: headlights, state: true}}") is None

    def test_single_quotes_instead_of_double_returns_none(self):
        assert parse_json_with_fallback("{'action': 'get_status', 'params': {}}") is None

    def test_trailing_comma_returns_none(self):
        assert parse_json_with_fallback('{"action": "get_status", "params": {},}') is None

    def test_nested_braces_extracts_full_balanced_object(self):
        text = 'noise before {"action": "set_climate", "params": {"power": true, "target_temp_c": 22, "fan_speed": 3}} noise after'
        result = parse_json_with_fallback(text)
        assert result == {
            "action": "set_climate",
            "params": {"power": True, "target_temp_c": 22, "fan_speed": 3},
        }

    def test_json_array_at_top_level_returns_none(self):
        # The DSL contract requires a top-level JSON *object*; a bare array
        # has no balanced `{...}` for the fallback extractor to find, and
        # json.loads() would succeed but yield a list, not a dict — either
        # way this must not be treated as a valid action.
        result = parse_json_with_fallback('[{"action": "get_status", "params": {}}]')
        assert result is None or isinstance(result, list)


class TestLLMActionSchema:
    def test_valid_action_parses(self):
        action = LLMAction(action="set_window", params={"window": "front_left", "position": 100})
        assert action.action == "set_window"
        assert action.params == {"window": "front_left", "position": 100}
        assert action.reasoning is None

    def test_extra_field_is_rejected(self):
        # extra="forbid" — this is the schema_attack category's core
        # assertion: any additional top-level field must raise, not be
        # silently ignored.
        with pytest.raises(ValidationError):
            LLMAction(
                action="set_window",
                params={"window": "front_left", "position": 100},
                override_security=True,
            )

    def test_missing_required_action_field_is_rejected(self):
        with pytest.raises(ValidationError):
            LLMAction(params={"window": "front_left", "position": 100})

    def test_missing_required_params_field_is_rejected(self):
        with pytest.raises(ValidationError):
            LLMAction(action="get_status")

    def test_wrong_type_for_action_is_rejected(self):
        with pytest.raises(ValidationError):
            LLMAction(action=123, params={})

    def test_wrong_type_for_params_is_rejected(self):
        # A string masquerading as the params object (e.g. a model emitting
        # `"params": "22"` instead of an object) must be rejected here,
        # before it can ever reach dsl_whitelist_range.
        with pytest.raises(ValidationError):
            LLMAction(action="set_climate", params="22")

    def test_reasoning_is_optional_and_defaults_to_none(self):
        action = LLMAction(action="get_status", params={})
        assert action.reasoning is None

    def test_reasoning_accepts_string_when_present(self):
        action = LLMAction(action="get_status", params={}, reasoning="checking vehicle status")
        assert action.reasoning == "checking vehicle status"
