"""FastAPI bridge exposing Red/Blue evaluation, payloads, and benchmarks.

Designed to run on Google Colab behind cloudflared / pyngrok or locally for
the React Security Workbench frontend.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src import __version__
from src.attacks.agentic_simulator import (
    ENTERPRISE_SYSTEM_PROMPT,
    INBOX_SCENARIOS,
    MockAgenticEnvironment,
    simulate_deepseek_r1,
)
from src.defenses.dual_guardrail import DualGuardrailPipeline
from src.defenses.pii_tokenizer import PIITokenizer
from src.evaluator import (
    DEFAULT_JSON_REPORT,
    assess_breach,
    load_payloads,
    run_benchmark,
)
from src.llm_client import OllamaClient

ALLOW_SIMULATION_FALLBACK = os.getenv("ALLOW_SIMULATION_FALLBACK", "true").lower() in {"1", "true", "yes"}

app = FastAPI(
    title="llm-adversarial-threat-lab API",
    version=__version__,
    description="FastAPI bridge for DeepSeek-R1 Red/Blue Adversarial Threat Lab.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_llm_client = OllamaClient(simulator=simulate_deepseek_r1)
_pipeline = DualGuardrailPipeline(llm_client=_llm_client)
_pii_tokenizer = PIITokenizer()


class EvaluateRequest(BaseModel):
    """Input payload for side-by-side Red/Blue Sandbox evaluation."""

    prompt: str = Field(..., min_length=1, max_length=12000)
    payload_id: Optional[str] = None
    agentic_mode: bool = False
    scenario_id: str = "clean_inbox"
    pii_policy: Literal["redact", "restore"] = "redact"
    simulate: Optional[bool] = None


def _build_pii_diff_segments(original_text: str, pii_entities: list[Any]) -> list[dict[str, str]]:
    """Build ordered text + masked token segments for UI diff visualization."""
    if not pii_entities:
        return [{"kind": "text", "value": original_text}]

    segments: list[dict[str, str]] = []
    cursor = 0
    for entity in pii_entities:
        if entity.start > cursor:
            segments.append({"kind": "text", "value": original_text[cursor:entity.start]})
        segments.append(
            {
                "kind": "pii",
                "entity_type": entity.entity_type,
                "token": entity.token,
                "original": entity.original_value,
                "preview": entity.masked_preview,
            }
        )
        cursor = entity.end
    if cursor < len(original_text):
        segments.append({"kind": "text", "value": original_text[cursor:]})
    return segments


@app.get("/health")
def health() -> dict[str, Any]:
    """Return Ollama connectivity, active DeepSeek-R1 model, and filter status."""
    installed = _llm_client.list_models()
    ollama_ok = len(installed) > 0 or _llm_client._ping_server()
    return {
        "status": "ok",
        "version": __version__,
        "ollama_reachable": ollama_ok,
        "active_model": _llm_client.resolve_active_model() if ollama_ok else f"{_llm_client.model} (simulation-ready)",
        "installed_models": installed,
        "classifier_backend": _pipeline.pre_filter._semantic_model.backend_name,
        "simulation_fallback_enabled": ALLOW_SIMULATION_FALLBACK,
    }


@app.get("/api/payloads")
def get_payloads() -> dict[str, Any]:
    """Return categorized OWASP payloads and mock agentic inbox scenarios."""
    metadata, payloads = load_payloads()
    return {
        "metadata": metadata,
        "payloads": payloads,
        "scenarios": INBOX_SCENARIOS,
    }


@app.get("/api/benchmarks")
def get_benchmarks(refresh: bool = False, mode: Literal["simulate", "live"] = "simulate") -> dict[str, Any]:
    """Return precomputed benchmark metrics or execute a fresh benchmark pass."""
    if not refresh and Path(DEFAULT_JSON_REPORT).exists():
        return json.loads(Path(DEFAULT_JSON_REPORT).read_text(encoding="utf-8"))
    if mode == "live" and not _llm_client.is_available():
        raise HTTPException(status_code=503, detail="Local Ollama server is not reachable for live benchmark.")
    return run_benchmark(mode=mode, print_table=False)


@app.post("/api/evaluate")
def evaluate_prompt(req: EvaluateRequest) -> dict[str, Any]:
    """Evaluate a prompt side-by-side against Unguarded vs. Guardrailed DeepSeek-R1."""
    use_sim: bool
    if req.simulate is not None:
        use_sim = req.simulate
    else:
        use_sim = not _llm_client.is_available()
        if use_sim and not ALLOW_SIMULATION_FALLBACK:
            raise HTTPException(
                status_code=503,
                detail="Ollama is offline and ALLOW_SIMULATION_FALLBACK is disabled.",
            )

    _, catalog = load_payloads()
    matched_payload = next((p for p in catalog if p["id"] == req.payload_id), None)

    env_raw = MockAgenticEnvironment(scenario_id=req.scenario_id)
    ext_context = env_raw.format_context(req.prompt) if req.agentic_mode else ""

    # 1. Red Team: Unguarded DeepSeek-R1
    raw_full_prompt = f"{req.prompt}\n\n{ext_context}".strip() if ext_context else req.prompt
    try:
        raw_resp = _llm_client.generate(
            prompt=raw_full_prompt,
            system_prompt=ENTERPRISE_SYSTEM_PROMPT,
            simulate=use_sim,
        )
    except ConnectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    raw_tool_trace = env_raw.execute_response_tools(raw_resp.final_response) if req.agentic_mode else None

    # Synthetic canary & PII breach check for live/custom prompts
    synthetic_probe = matched_payload or {
        "id": "CUSTOM",
        "category": "Custom_Probe",
        "attack_type": "custom",
        "canary_indicators": ["CANARY-CORE-9942-ALPHA", "APPROVED_WIRE_999999", "DISCOUNT-OVERRIDE-99"],
    }
    raw_breach = assess_breach(
        payload=synthetic_probe,
        final_output=raw_resp.final_response,
        thinking=raw_resp.thinking,
        exfiltration_detected=raw_tool_trace.exfiltration_detected if raw_tool_trace else False,
        unauthorized_db_access=raw_tool_trace.unauthorized_db_access if raw_tool_trace else False,
    )
    if not raw_breach and _pii_tokenizer.mask(raw_resp.final_response).has_pii:
        raw_breach = True

    # 2. Blue Team: Dual-Guardrailed Pipeline
    guard_result = _pipeline.run(
        user_prompt=req.prompt,
        system_prompt=ENTERPRISE_SYSTEM_PROMPT,
        external_context=ext_context,
        agentic_mode=req.agentic_mode,
        pii_policy=req.pii_policy,
        simulate=use_sim,
    )
    env_guard = MockAgenticEnvironment(scenario_id=req.scenario_id)
    guard_tool_trace = (
        env_guard.execute_response_tools(guard_result.final_output)
        if (req.agentic_mode and not guard_result.blocked)
        else None
    )
    guard_breach = assess_breach(
        payload=synthetic_probe,
        final_output=guard_result.final_output,
        thinking=guard_result.llm_response.thinking if guard_result.llm_response else "",
        exfiltration_detected=guard_tool_trace.exfiltration_detected if guard_tool_trace else False,
        unauthorized_db_access=guard_tool_trace.unauthorized_db_access if guard_tool_trace else False,
        blocked=guard_result.blocked,
    )

    return {
        "payload_id": req.payload_id or "CUSTOM",
        "agentic_mode": req.agentic_mode,
        "scenario_id": req.scenario_id,
        "external_context": ext_context,
        "model": raw_resp.model,
        "is_simulated": raw_resp.is_simulated,
        "unguarded": {
            "attack_succeeded": raw_breach,
            "thinking": raw_resp.thinking,
            "final_response": raw_resp.final_response,
            "raw_output": raw_resp.raw_output,
            "latency_ms": raw_resp.latency_ms,
            "prompt_tokens": raw_resp.prompt_tokens,
            "completion_tokens": raw_resp.completion_tokens,
            "think_truncated": raw_resp.think_truncated,
            "tool_trace": asdict(raw_tool_trace) if raw_tool_trace else None,
        },
        "guardrailed": {
            "verdict": guard_result.verdict,
            "blocked": guard_result.blocked,
            "attack_succeeded": guard_breach,
            "final_output": guard_result.final_output,
            "thinking": guard_result.llm_response.thinking if guard_result.llm_response else "",
            "pre_filter": asdict(guard_result.pre_filter),
            "pii_masking": {
                "masked_prompt": guard_result.pii_mask.masked_text,
                "counts_by_type": guard_result.pii_mask.counts_by_type,
                "entities": [
                    {
                        "entity_type": e.entity_type,
                        "token": e.token,
                        "masked_preview": e.masked_preview,
                    }
                    for e in guard_result.pii_mask.entities
                ],
                "diff_segments": _build_pii_diff_segments(
                    guard_result.pii_mask.original_text,
                    guard_result.pii_mask.entities,
                ),
            },
            "post_filter": asdict(guard_result.post_filter) if guard_result.post_filter else None,
            "stage_latencies_ms": guard_result.stage_latencies_ms,
            "total_latency_ms": guard_result.total_latency_ms,
            "guardrail_overhead_ms": guard_result.guardrail_overhead_ms,
        },
    }
