# EU AI Act Risk & Compliance Assessment (`llm-adversarial-threat-lab`)

This assessment documents how the workbench's threat models and technical safeguards align with **Regulation (EU) 2024/1689 (EU AI Act)** obligations across risk tiers.

## 1. Risk Tier Classification Scope
| Lab Subsystem / Deployment Context | EU AI Act Risk Tier | Rationale & Legal Reference |
| :--- | :--- | :--- |
| Enterprise Agentic Tool-Calling Assistant (`read_inbox`, `query_db`, `send_email`) handling HR/KYC/Finance data | **High-Risk** *(Annex III / Articles 9, 10, 14, 15)* | Automated access to HR/payroll records (`payroll_pii`) and KYC identifiers (`IN_AADHAAR`, `IN_PAN`, `SSN`) places the system under strict data governance, human oversight, and cybersecurity duties. |
| Customer-Facing Conversational AI / Assistant | **Limited Risk** *(Article 50)* | Requires clear transparency that users are interacting with an AI system and protection against system-instruction extraction (`LLM01 / LLM07`). |
| Offline Security Benchmark & Benign Control Suite (`BENIGN-01..08`) | **Minimal Risk** | Internal engineering R&D and guardrail calibration tooling. |

## 2. Article-by-Article Control Mapping

### Article 9 — Risk Management System
- **Requirement:** Continuous identification, estimation, evaluation, and mitigation of foreseeable misuse and adversarial risks throughout the lifecycle.
- **Implementation:** Automated Red/Blue regression testing via [src/evaluator.py](../src/evaluator.py) and live side-by-side inspection in [frontend/src/components/SandboxView.jsx](../frontend/src/components/SandboxView.jsx).

### Article 10 — Data and Data Governance
- **Requirement:** Data minimization and protection of personal data processed by AI pipelines.
- **Implementation:** [src/defenses/pii_tokenizer.py](../src/defenses/pii_tokenizer.py) strips raw personal identifiers (`EMAIL`, `SSN`, `IP_ADDRESS`, `IN_AADHAAR`, `IN_PAN`) and secrets (`API_KEY`) into opaque `<PII_TYPE_ID>` tokens *prior* to model inference, ensuring DeepSeek-R1 never observes raw personal data during reasoning (`<think>`).

### Article 14 — Human Oversight (Agentic Controls)
- **Requirement:** Prevent automation bias and unintended autonomous execution with irreversible external impact.
- **Implementation:** `PostInferenceFilter` in [src/defenses/dual_guardrail.py](../src/defenses/dual_guardrail.py) blocks unauthorized external `send_email` calls and restricted SQL queries (`api_credentials`, `payroll_pii`), forcing explicit human approval gates outside `@acme-corp.example`.

### Article 15 — Accuracy, Robustness, and Cybersecurity
- **Requirement:** High-risk AI systems must be resilient against attempts by unauthorized third parties to alter their use, outputs, or performance (explicitly referencing prompt injection and data poisoning).
- **Implementation:** Dual-layer defense combining `PreInferenceFilter` (structural normalization, Base64 decoding, `<think>` spoof detection, TF-IDF + Logistic Regression semantic scoring) and `PostInferenceFilter` (reasoning leak stripping, canary redaction, tool ACLs).
