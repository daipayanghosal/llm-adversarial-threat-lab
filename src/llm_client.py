"""Isolated local LLM runtime client for Ollama + DeepSeek-R1.

Provides:
- Local Ollama HTTP integration (/api/chat and /api/tags) with automatic
  deepseek-r1:7b -> deepseek-r1:1.5b fallback.
- Dedicated parser separating DeepSeek-R1 <think>...</think> reasoning blocks
  from the user-facing final response.
- Optional deterministic simulation backend for CI tests and offline evaluation.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

import requests

DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
PRIMARY_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:7b")
FALLBACK_MODEL = os.getenv("OLLAMA_FALLBACK_MODEL", "deepseek-r1:1.5b")

# Matches complete <think>...</think> blocks case-insensitively across newlines.
_THINK_BLOCK_RE = re.compile(r"<think>(.*?)</think>", re.IGNORECASE | re.DOTALL)
_OPEN_THINK_RE = re.compile(r"<think>(.*)$", re.IGNORECASE | re.DOTALL)
_CLOSE_THINK_ONLY_RE = re.compile(r"^(.*?)</think>(.*)$", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class ParsedThinking:
    """Structured split of a DeepSeek-R1 completion."""

    thinking: str
    final_response: str
    think_truncated: bool = False
    has_think_tags: bool = False


@dataclass(frozen=True)
class LLMResponse:
    """Full inference result returned by OllamaClient."""

    model: str
    raw_output: str
    thinking: str
    final_response: str
    latency_ms: float
    prompt_tokens: int
    completion_tokens: int
    think_truncated: bool
    is_simulated: bool


def parse_deepseek_response(raw_text: str) -> ParsedThinking:
    """Separate DeepSeek-R1 <think>...</think> reasoning traces from final output.

    Handles four real-world DeepSeek-R1 formatting variants:
    1. Standard `<think>...</think> final answer`.
    2. Multiple `<think>...</think>` blocks (concatenated cleanly).
    3. Template-injected opening tag (`reasoning</think> final answer`).
    4. Truncated stream (`<think>unfinished reasoning` without closing tag).
    """
    text = (raw_text or "").strip()
    if not text:
        return ParsedThinking(thinking="", final_response="", think_truncated=False, has_think_tags=False)

    matches = list(_THINK_BLOCK_RE.finditer(text))
    if matches:
        thinking_parts = [m.group(1).strip() for m in matches if m.group(1).strip()]
        cleaned = _THINK_BLOCK_RE.sub("", text).strip()
        # Handle trailing unclosed <think> if max_tokens cut off a second block
        trailing_open = _OPEN_THINK_RE.search(cleaned)
        truncated = False
        if trailing_open:
            if trailing_open.group(1).strip():
                thinking_parts.append(trailing_open.group(1).strip())
            cleaned = _OPEN_THINK_RE.sub("", cleaned).strip()
            truncated = True
        return ParsedThinking(
            thinking="\n\n".join(thinking_parts),
            final_response=cleaned,
            think_truncated=truncated,
            has_think_tags=True,
        )

    # Case 3: Ollama chat template emitted opening <think> in prompt prefix,
    # so completion contains only a closing </think>.
    if "</think>" in text.lower() and "<think>" not in text.lower():
        close_match = _CLOSE_THINK_ONLY_RE.match(text)
        if close_match:
            return ParsedThinking(
                thinking=close_match.group(1).strip(),
                final_response=close_match.group(2).strip(),
                think_truncated=False,
                has_think_tags=True,
            )

    # Case 4: Unclosed <think> (generation hit num_predict before finishing thought)
    open_match = _OPEN_THINK_RE.search(text)
    if open_match:
        prefix = text[: open_match.start()].strip()
        thought = open_match.group(1).strip()
        return ParsedThinking(
            thinking=thought,
            final_response=prefix,
            think_truncated=True,
            has_think_tags=True,
        )

    return ParsedThinking(
        thinking="",
        final_response=text,
        think_truncated=False,
        has_think_tags=False,
    )


class OllamaClient:
    """Lightweight wrapper around a local Ollama daemon for DeepSeek-R1 inference."""

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model: str = PRIMARY_MODEL,
        fallback_model: str = FALLBACK_MODEL,
        timeout_seconds: float = 90.0,
        simulator: Optional[Callable[[str, str], str]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.fallback_model = fallback_model
        self.timeout_seconds = timeout_seconds
        self._simulator = simulator

    def list_models(self) -> list[str]:
        """Return installed Ollama model tags, or an empty list if unreachable."""
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=3.0)
            resp.raise_for_status()
            data = resp.json()
            return [m["name"] for m in data.get("models", []) if "name" in m]
        except requests.RequestException:
            return []

    def is_available(self) -> bool:
        """Return True when the local Ollama server responds to /api/tags."""
        return len(self.list_models()) > 0 or self._ping_server()

    def _ping_server(self) -> bool:
        try:
            resp = requests.get(f"{self.base_url}/api/version", timeout=2.0)
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def resolve_active_model(self) -> str:
        """Select primary model if installed, otherwise fall back to 1.5b or any deepseek-r1 tag."""
        installed = self.list_models()
        if not installed:
            return self.model
        if self.model in installed:
            return self.model
        if self.fallback_model in installed:
            return self.fallback_model
        for tag in installed:
            if "deepseek-r1" in tag.lower():
                return tag
        return installed[0]

    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.2,
        max_tokens: int = 512,
        simulate: bool = False,
    ) -> LLMResponse:
        """Execute chat completion via Ollama or an explicit deterministic simulator."""
        if simulate:
            if self._simulator is None:
                raise RuntimeError("Simulation mode requested but no simulator callback is configured.")
            t0 = time.perf_counter()
            raw = self._simulator(system_prompt, prompt)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            parsed = parse_deepseek_response(raw)
            return LLMResponse(
                model=f"{self.model} (simulated)",
                raw_output=raw,
                thinking=parsed.thinking,
                final_response=parsed.final_response,
                latency_ms=round(elapsed_ms, 2),
                prompt_tokens=max(1, len((system_prompt + " " + prompt).split())),
                completion_tokens=max(1, len(raw.split())),
                think_truncated=parsed.think_truncated,
                is_simulated=True,
            )

        chosen_model = self.resolve_active_model()
        candidates = [chosen_model]
        if self.fallback_model not in candidates:
            candidates.append(self.fallback_model)

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        last_err: Optional[Exception] = None
        for model_name in candidates:
            payload: dict[str, Any] = {
                "model": model_name,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
            try:
                t0 = time.perf_counter()
                resp = requests.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                resp.raise_for_status()
                body = resp.json()
                raw = body.get("message", {}).get("content", "")
                parsed = parse_deepseek_response(raw)
                return LLMResponse(
                    model=model_name,
                    raw_output=raw,
                    thinking=parsed.thinking,
                    final_response=parsed.final_response,
                    latency_ms=round(elapsed_ms, 2),
                    prompt_tokens=int(body.get("prompt_eval_count", 0)),
                    completion_tokens=int(body.get("eval_count", 0)),
                    think_truncated=parsed.think_truncated,
                    is_simulated=False,
                )
            except requests.RequestException as exc:
                last_err = exc
                continue

        raise ConnectionError(
            f"Unable to reach local Ollama at {self.base_url} for models {candidates}: {last_err}"
        )
