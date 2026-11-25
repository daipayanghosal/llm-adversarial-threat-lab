# Red Team & Guardrail Audit Report (`llm-adversarial-threat-lab`)

- **Target Runtime:** Ollama + Distilled DeepSeek-R1 (`deepseek-r1:7b`, fallback `deepseek-r1:1.5b`)
- **Standard Covered:** **OWASP Top 10 for Large Language Model Applications (2025)** (`LLM01`–`LLM10`)
- **Evaluation Harness:** [src/evaluator.py](../src/evaluator.py)
- **Dataset:** 40 total probes (32 adversarial payloads across all 10 OWASP categories + 8 benign control prompts)
- **Execution Mode Reported:** `simulate` (deterministic baseline verification with live Python `DualGuardrailPipeline` and `PIITokenizer` execution; re-run `python -m src.evaluator --mode live` on Google Colab T4 to capture hardware GPU inference timings)

> [!NOTE]
> The metrics below come directly from [reports/benchmark_results.json](benchmark_results.json) generated after the final test pass. In `simulate` mode, LLM generation latency reflects deterministic simulator timing (`~0.05 ms`), while guardrail latency reflects actual measured CPU time of `PreInferenceFilter`, `PIITokenizer`, and `PostInferenceFilter`.

---

## 1. Executive Telemetry Summary

| Metric | Unguarded DeepSeek-R1 | Dual-Guardrailed Pipeline | Delta / Target |
| :--- | :---: | :---: | :---: |
| **Overall Attack Success Rate (ASR)** | **100.0%** (32 / 32) | **0.0%** (0 / 32) | **-100.0 percentage points** |
| **Benign False Positive Rate (FPR)** | **0.0%** (0 / 8) | **0.0%** (0 / 8) | `0.0%` false blocks |
| **Mean Guardrail Overhead** | `0.00 ms` | **`0.15 ms`** | Sub-millisecond CPU overhead |
| **P95 Guardrail Overhead** | `0.00 ms` | **`0.28 ms`** | Negligible vs. LLM generation |

![OWASP LLM Top 10 Defense Benchmark](asr_comparison.png)

---

## 2. Category-Level Breakdown (All 10 Textbook Categories)

| OWASP Category | Payloads | Unguarded ASR | Guardrailed ASR | Mean Guardrail Overhead |
| :--- | :---: | :---: | :---: | :---: |
| `LLM01_Prompt_Injection` | 4 | 100.0% | 0.0% | 0.17 ms |
| `LLM02_Sensitive_Information_Disclosure` | 4 | 100.0% | 0.0% | 0.16 ms |
| `LLM03_Supply_Chain` | 3 | 100.0% | 0.0% | 0.11 ms |
| `LLM04_Data_and_Model_Poisoning` | 3 | 100.0% | 0.0% | 0.12 ms |
| `LLM05_Improper_Output_Handling` | 3 | 100.0% | 0.0% | 0.10 ms |
| `LLM06_Excessive_Agency` | 3 | 100.0% | 0.0% | 0.23 ms |
| `LLM07_System_Prompt_Leakage` | 3 | 100.0% | 0.0% | 0.11 ms |
| `LLM08_Vector_and_Embedding_Weaknesses` | 3 | 100.0% | 0.0% | 0.21 ms |
| `LLM09_Misinformation` | 3 | 100.0% | 0.0% | 0.09 ms |
| `LLM10_Unbounded_Consumption` | 3 | 100.0% | 0.0% | 0.15 ms |

---

## 3. Residual Risks & Production Hardening Recommendations

- **Supply Chain & Package Verification (`LLM03` / `LLM09`):** Pair prompt-level heuristics with real SBOM / lockfile signature checks and live PyPI/OSV advisory verification before executing any model-recommended command.
- **RAG Tenant Isolation (`LLM08`):** Enforce tenant ID filtering inside vector database query predicates at the data layer, never relying solely on post-retrieval text filters.
- **Live GPU Verification:** Execute [notebooks/02_red_team_and_benchmarks.ipynb](../notebooks/02_red_team_and_benchmarks.ipynb) on Colab T4 to record live `deepseek-r1:7b` generation latencies across all 40 probes.
