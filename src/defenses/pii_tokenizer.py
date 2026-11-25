"""Reversible PII Tokenization Engine (OWASP LLM06 Mitigation).

Masks sensitive entities (emails, API keys, US SSNs, IPv4 addresses, Indian
Aadhaar numbers, and Indian PAN numbers) into deterministic <PII_TYPE_ID>
tokens prior to LLM inference, and restores or redacts them post-inference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class DetectedPII:
    """Single detected PII entity with offsets and replacement token."""

    entity_type: str
    token: str
    original_value: str
    masked_preview: str
    start: int
    end: int


@dataclass
class MaskResult:
    """Structured output from PIITokenizer.mask()."""

    original_text: str
    masked_text: str
    token_map: dict[str, str] = field(default_factory=dict)
    entities: list[DetectedPII] = field(default_factory=list)
    counts_by_type: dict[str, int] = field(default_factory=dict)

    @property
    def has_pii(self) -> bool:
        return len(self.entities) > 0


# Ordered from most specific secret/identifier to broadest numeric/network pattern
# so compound strings (e.g. emails or API keys) are never split by simpler rules.
_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "API_KEY",
        re.compile(
            r"\b(?:sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{14,}|"
            r"AKIA[0-9A-Z]{16}|"
            r"ghp_[A-Za-z0-9]{20,}|"
            r"xox[baprs]-[A-Za-z0-9-]{10,}|"
            r"AIza[0-9A-Za-z_-]{35})\b"
        ),
    ),
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "IN_PAN",
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    ),
    (
        "SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        "IN_AADHAAR",
        re.compile(
            r"(?<!\d)(?:[2-9]\d{3}[ -]\d{4}[ -]\d{4})(?!\d)|"
            r"(?<=(?i:aadhaar)[:\s=-])[2-9]\d{11}(?!\d)|"
            r"(?<=(?i:uidai)[:\s=-])[2-9]\d{11}(?!\d)"
        ),
    ),
    (
        "IP_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
]


def _make_preview(value: str) -> str:
    """Create a redacted preview for telemetry tables without leaking secrets."""
    if len(value) <= 6:
        return "***"
    if "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:2]}***@{domain}"
    return f"{value[:3]}***{value[-3:]}"


class PIITokenizer:
    """Deterministic, reversible PII masking and restoration engine."""

    def mask(self, text: str) -> MaskResult:
        """Detect supported PII types and replace them with <PII_TYPE_ID> tokens."""
        if not text:
            return MaskResult(original_text=text, masked_text=text)

        raw_matches: list[tuple[int, int, str, str]] = []
        occupied: list[tuple[int, int]] = []

        for entity_type, pattern in _PII_PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span()
                if any(not (end <= occ_start or start >= occ_end) for occ_start, occ_end in occupied):
                    continue
                occupied.append((start, end))
                raw_matches.append((start, end, entity_type, match.group(0)))

        # Sort left-to-right to assign deterministic sequential token IDs.
        raw_matches.sort(key=lambda item: item[0])

        value_to_token: dict[tuple[str, str], str] = {}
        type_counters: dict[str, int] = {}
        token_map: dict[str, str] = {}
        entities: list[DetectedPII] = []

        chunks: list[str] = []
        cursor = 0

        for start, end, entity_type, value in raw_matches:
            key = (entity_type, value)
            if key not in value_to_token:
                type_counters[entity_type] = type_counters.get(entity_type, 0) + 1
                token = f"<PII_{entity_type}_{type_counters[entity_type]}>"
                value_to_token[key] = token
                token_map[token] = value
            else:
                token = value_to_token[key]

            chunks.append(text[cursor:start])
            chunks.append(token)
            cursor = end

            entities.append(
                DetectedPII(
                    entity_type=entity_type,
                    token=token,
                    original_value=value,
                    masked_preview=_make_preview(value),
                    start=start,
                    end=end,
                )
            )

        chunks.append(text[cursor:])
        counts: dict[str, int] = {}
        for entity in entities:
            counts[entity.entity_type] = counts.get(entity.entity_type, 0) + 1

        return MaskResult(
            original_text=text,
            masked_text="".join(chunks),
            token_map=token_map,
            entities=entities,
            counts_by_type=counts,
        )

    def restore(
        self,
        text: str,
        token_map: dict[str, str],
        policy: Literal["restore", "redact"] = "redact",
    ) -> str:
        """Restore masked tokens for authorized callers or harden them as redacted."""
        if not text:
            return text

        output = text
        for token, original_value in token_map.items():
            if token not in output:
                continue
            if policy == "restore":
                output = output.replace(token, original_value)
            else:
                # Strip angle brackets into an unmistakable redaction marker
                inner = token.strip("<>")
                output = output.replace(token, f"[REDACTED:{inner}]")

        if policy == "redact":
            # Belt-and-suspenders: redact any raw PII recalled or echoed by the LLM.
            recheck = self.mask(output)
            if recheck.has_pii:
                remapped = recheck.masked_text
                for token in recheck.token_map:
                    inner = token.strip("<>")
                    remapped = remapped.replace(token, f"[REDACTED:{inner}]")
                output = remapped

        return output
