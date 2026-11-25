# NIST AI RMF 1.0 Alignment (`llm-adversarial-threat-lab`)

Mapping of `llm-adversarial-threat-lab` architecture, telemetry, and guardrails to the **NIST Artificial Intelligence Risk Management Framework (AI RMF 1.0)** core functions: **GOVERN, MAP, MEASURE, MANAGE**.

## 1. GOVERN — Accountability, Policies & Data Protection
- **GOVERN 1.2 (Legal & Regulatory Alignment):** Enforces pre-inference tokenization of regional and global PII identifiers (`EMAIL`, `API_KEY`, `SSN`, `IP_ADDRESS`, `IN_AADHAAR`, `IN_PAN`) in [src/defenses/pii_tokenizer.py](../src/defenses/pii_tokenizer.py).
- **GOVERN 4.2 (Organizational Risk Tolerance & Tool Boundaries):** Codifies explicit tool-calling constraints (`@acme-corp.example` recipient boundary, restricted table deny list for `api_credentials` and `payroll_pii`) inside [src/defenses/dual_guardrail.py](../src/defenses/dual_guardrail.py).

## 2. MAP — Context Establishment & Threat Identification
- **MAP 2.3 (Scientific & Adversarial Threat Enumeration):** Categorizes 30 adversarial test probes across direct jailbreaks, `<think>` reasoning manipulation, system prompt extraction, PII disclosure, and indirect agentic injection in [src/attacks/payloads.json](../src/attacks/payloads.json).
- **MAP 3.4 (Operator & Down-Stream Dependency Risks):** Models indirect prompt injection originating from untrusted external feeds (`read_inbox()` HTML comments, poisoned invoices, calendar invites, and `query_db()` notes) via [src/attacks/agentic_simulator.py](../src/attacks/agentic_simulator.py).
- **MAP 5.1 (Likelihood & Impact Characterization):** Captures DeepSeek-R1 chain-of-thought (`<think>`) risk pathways separately from final outputs using [src/llm_client.py](../src/llm_client.py).

## 3. MEASURE — Quantitative Testing & Telemetry
- **MEASURE 2.5 & 2.6 (Safety, Security & Utility Metrics):** [src/evaluator.py](../src/evaluator.py) measures Attack Success Rate (ASR %), Benign False Positive Rate (FPR %), and stage-by-stage guardrail latency overhead (`ms`), outputting [reports/benchmark_results.json](../reports/benchmark_results.json) and [reports/asr_comparison.png](../reports/asr_comparison.png).
- **MEASURE 2.7 (Adversarial Robustness Verification):** Automated pytest checks in [tests/test_lab_suite.py](../tests/test_lab_suite.py) verify parser behavior, PII masking/restoration invariants, guardrail verdicts, and FastAPI endpoint contracts on every build.

## 4. MANAGE — Runtime Mitigation & Incident Auditability
- **MANAGE 1.3 & 2.2 (Response & Containment):** `PreInferenceFilter` blocks high-risk injection attempts before GPU inference; `PostInferenceFilter` blocks leaked canaries, stray `<think>` tags, and unauthorized `TOOL_CALL` emissions.
- **MANAGE 2.4 & 4.1 (Continuous Monitoring):** The React Workbench ([frontend/src/components/TelemetryView.jsx](../frontend/src/components/TelemetryView.jsx) and [frontend/src/components/SandboxView.jsx](../frontend/src/components/SandboxView.jsx)) preserves inspectable stage latencies, risk scores, and PII masking diffs for security operations review.
