# Paper Brief — Tobin South, "Private, Verifiable, and Auditable AI Systems" (arXiv:2509.00085)

Source: `/Users/aaryanguglani/Documents/workspace1/glyph/arXiv-2509.00085v1/`. Section anchors below refer to thesis chapter files.

---

## 1. Authenticated Delegation framework (Chapter 4, `authenticated-delegation.tex`)

The thesis defines authenticated delegation as a process by which third parties can verify that **(a)** the interacting entity is an AI agent, **(b)** the agent is acting on behalf of a specific human user, and **(c)** the agent has been granted the listed permissions. It distinguishes three concepts: **authentication** (who the entity is), **authorization** (what it may do), and **auditability** (third-party inspectability of unaltered claims).

### Three-token architecture
The framework extends OAuth 2.0 / OpenID Connect (OIDC) and proposes three identity-related tokens (verbatim from `authenticated-delegation.tex`, "Token-based authentication framework"):

1. **User's ID-token** — the existing OIDC ID-token signed by the OpenID Provider (OP). Represents the human user; identical to a normal login.
2. **Agent-ID token** — issued for the AI agent registered as an OAuth 2.0 Native Client (the agent owner controls all keying material). Carries the unique agent identifier plus optional metadata such as system documentation, capabilities, limitations, and relationships to other AI systems (per `chan2024ids`).
3. **Delegation Token** — newly introduced. **Issued and signed by the human delegator** (not the OP). Carries **references to (e.g., hash of) the corresponding User's ID-token and the Agent-ID token**. Specifies validity conditions (expiration, revocation endpoint), scope/permissions, optional summarized goal, and optional logging/audit URLs. Must be digitally signed by the user "to prevent forgeries and ensure that the user knowingly granted the AI agent the listed privileges".

These can be embedded in (or referenced from) a W3C Verifiable Credential, with a hybrid VC/OIDC path explicitly noted as the most pragmatic deployment.

### Protocol flow (Figure: `OIDC-AI`, `authenticated-delegation.tex` lines 226-268)
1. User authenticates to the OP (steps 1 & 2 of the diagram).
2. User registers the AI Agent with the OP — extending OAuth 2.0 client registration so the agent is designated a delegate/surrogate. Registration may be automatic when an agent is created via a vendor.
3. User issues a Delegation Token authorizing the agent.
4. Agent uses that token (carried as VC or OIDC token) to access third-party Resource Servers; verification of both User ID-token and Delegation Token can be performed at the standard OP. UMA is suggested for users with multiple agents acting as distributed RSes under a single policy point.

### What each party verifies
- **User**: identity to OP; signs Delegation Token.
- **Agent (Native Client)**: holds keying material, presents tokens to services.
- **Service / Relying Party**: that the Delegation Token references a valid User ID-token *and* a properly issued Agent-ID token, both validated against the trusted OP; that delegation scope, expiry, and revocation status are valid.

### Scope / permissions
The thesis argues for **resource scoping with structured permissions** (XACML, ODRL, OBAC, ROWLBAC, KaOS, Multi-OrBAC, URL allow/blocklists) as the primary enforcement mechanism, distinguished from **task scoping**. Natural-language scoping is permitted only as an interface; an LLM converts NL constraints into structured policies (e.g., XACML / SQL ACLs / JSON), which a human reviews and approves before the structured rule becomes the binding artifact. Authentication flows (per-action prompts) are layered for borderline cases. Inter-agent scoping forwards Alice's authorizations to Bob, who responds with a structured interpretation that is logged and approved.

---

## 2. ZK requirements (Chapter 2)

### 2.1 Verifiable evaluations of ML models — `verifyevals.tex`
**Thesis-proven implementation** (built on the `ezkl` toolkit + Halo2 + KZG SRS).

- **Setup**: $\text{Setup}(1^{\lambda}, W, f) \rightarrow (pk, vk)$ — a circuit derived from the ONNX graph of the model, with weights $W$ as private inputs.
- **Prove**: $\text{Prove}(pk, W, x, y) \rightarrow \pi \supset \{H(W), y\}$ — proof commits to (i) input/output pair, (ii) the **model weight hash $H(W)$** (via a ZKG hashing of weights, "ezkl2023zerooverheadhashing").
- **Aggregation**: bundle of per-inference proofs OR a custom Halo2 aggregation circuit producing a single proof attesting to a metric (accuracy, confusion matrix).
- **Challenge model**: an auditor presents $(x^*, y^*)$ post-hoc and asks the provider to produce $\pi^*$ with the same $pk$ and matching $H(W)$. "Predict, then prove" allows the witness to be generated cheaply at inference time and the proof finalized later.

**Security properties claimed** (verbatim, "Security Properties"): correctness, soundness, **confidentiality of the model weights**, integrity, non-repudiation, succinctness, non-interactivity. Built atop Halo2 + Perpetual Powers of Tau ceremony for the SRS (trusted setup; toxic-waste assumption).

### 2.2 Partial ZK — `partialzk.tex`
**Thesis proposal / sketch.** Selectively prove only the *private* sub-computation of a model: e.g., a classifier head $HWx$ on top of a public backbone, or LoRA adapters $BAx$. Public layers run in the clear; only privacy-relevant slices enter the circuit. Threat noted: enough public input/output pairs can let an adversary reconstruct the small private slice (worse for low-rank LoRA).

### 2.3 zkTax / portable data — `zktax.tex`
**Three-service model**:
1. **Trusted Data Source (TDS)**: signs $H(x)$, returning $(x, S)$ where $S = \text{sign}(sk, H(x))$.
2. **Redact & Prove Service**: ZK circuit proves redacted/transformed $x'$ is consistent with the TDS-signed $x$, output $\pi_{x'}$.
3. **Verification Service**: anyone with the TDS public key checks $(x', \pi_{x'}, S)$.

Explicitly noted: **the ZK proof attests only to the transformation, not the ground-truth authenticity of the data; that authenticity comes from the root of trust (TDS signature, hardware attestation, or VC issuer).**

---

## 3. Privacy / TEE story (Chapter 3 `communitytrans.tex`, Chapter 4 `phc.tex`)

### TEE / Confidential compute requirements (Community Transformers, `communitytrans.tex`)
The thesis calls for TEEs (Intel SGX, AMD SEV, ARM TrustZone, NVIDIA H100 Confidential Computing) and lists four required hardware properties:

- **Confidentiality (memory encryption)** — protects against snooping / cold boot.
- **Integrity** — code is protected from host OS / hypervisor modification.
- **Attestation** — the enclave cryptographically proves *what code* is running and that the hardware is genuine. Must let a remote party verify (i) genuine vendor hardware, (ii) properly initialized TEE, (iii) the code measurement matches a known/expected hash.
- **Sealing** — TEE-instance-bound encryption key allowing state to be persisted outside the enclave and decrypted only by the same TEE instance.

Protocol primitives required: TEE keypair $(pk_{TEE}, sk_{TEE})$ externalized, client encrypts queries $E_{pk_{TEE}}(X)$, decryption only inside the enclave, retrieval $R$ over $C^{safe}/C^{open}$ entirely in the enclave, optional ORAM for memory-access side channels (flagged as future work), threshold-signature governance (FROST) for admin actions.

### Threat model
Semi-honest adversary, hardware vendor trusted, host OS/hypervisor *not* trusted. Side-channel mitigation requires the working set to fit in enclave memory or use ORAM. End-to-end confidentiality requires confidential GPU (H100) for inference, not just CPU TEE for retrieval.

### Personhood Credentials (`phc.tex`)
Two foundational requirements: **credential limits** (one per person from issuer) and **unlinkable pseudonymity** (verified via ZK proof; service-specific pseudonyms; unlinkable across services even with collusion). PHCs explicitly compose with authenticated delegation: the human delegator's PHC is referenced from the Delegation Token to establish the principal is a real person without revealing identity.

---

## 4. Auditability (Chapter 3)

### PRAG (`PRAG.tex`)
End-to-end MPC-based private retrieval over a secret-shared distributed vector DB. Trust model: $n_{servers}$ servers, semi-honest, honest majority $t < n_{servers}/2$, Shamir secret sharing over $\mathbb{F}_p$. Distance calc, top-k, and an MPC-friendly inverted-file index are the novel pieces. Sublinear server-side communication, constant client-side. **Audit/log artifact**: the protocol does not itself produce an audit trail beyond the secret-shared reads; auditability emerges from the RAG pattern (ex-post inspection of which documents were retrieved).

### NLR-RAG / "Transparency by design" (`nlrRAG.tex`)
Defines **auditability** as "the ability to identify what records were used by a machine-learning system to generate a specific output", and **updatability** as the ability to modify or delete those records (mapped to GDPR rectification / right-to-be-forgotten and CCPA correction/deletion). RAG provides a natural audit trail: each retrieved chunk is identifiable. Required artifacts: provenance pointer per retrieval, ability to delete/modify the underlying record, separation of pre-training data, retrieved external data, and personal private data.

### What is logged where (Chapter 5 vignette, `chapter-5.tex`)
"Holographic graph logs where chains of cryptographic hashes linked each step": each component (delegation grant, PRAG retrieval, model attestation lookup, agent action) emits a small attestation (a digital signature or lightweight ZK proof) hash-linked into the audit chain. The thesis explicitly calls these "small, computationally inexpensive attestations… cryptographically linking actions and data access events to create a verifiable audit trail without logging sensitive intermediate data".

---

## 5. Threat model and security properties

Properties claimed across the thesis:

- **zkSNARK eval** (`verifyevals.tex` "Security Properties"): correctness, soundness, weight confidentiality, integrity, non-repudiation, succinctness, non-interactivity.
- **Two threat models** for verifiable evals: TM#1 — provider lies about a public benchmark; TM#2 — provider swaps the model at inference. TM#2 requires a per-inference proof of $H(W)$ match.
- **PRAG**: semi-honest, honest majority of servers, no single party sees query or DB.
- **TEE**: trust hardware vendor + attestation service; do not trust host OS/hypervisor; need to mitigate memory-access side channels.
- **Authenticated delegation**: token freshness, revocation endpoints, privacy risks of OP correlating activity (OP becomes a single surveillance point — explicitly noted as a limitation).
- **Roots of trust** (Chapter 5 §1, "Root of Trust"): cryptographic proofs verify computation integrity over inputs but do **not** vouch for the authenticity of the original inputs unless anchored — examples given: TEE attestation, signed VC, signed manifest from a trusted authority.

---

## 6. Out-of-scope / future work — the GAP that GLYPH is filling

The thesis explicitly defers or omits the following:

- **No on-chain verification.** Blockchains are mentioned only twice in passing: (i) `verifyevals.tex` notes "this zero-knowledge aggregation step makes sense when posting model inferences to a blockchain" — but no design is given; (ii) Chapter 4 mentions Vitalik's `buterin_what_2023` and a single sentence acknowledging blockchain-anchored credentials. There is **no Solana/EVM design, no on-chain verifier circuit, no transaction model**.
- **No replay protection.** Token freshness for delegation is named as a concern (§5.3.1 "Problems with an OpenID Connect approach") but no nonce, sequence number, or anti-replay construction is specified. The Delegation Token only has expiration + revocation endpoint.
- **No canonicalization spec.** The thesis hashes "data" or "weights" or signs $H(x)$ but never specifies a canonical encoding for the User-ID-token / Agent-ID-token / Delegation-Token bundle. It says "carries references to (e.g., hash of) the corresponding user's ID token and the agent's Agent-ID token" — the *e.g.* is doing a lot of work; the binding format is unspecified.
- **No deterministic transcript / commitment for agent actions.** Chapter 5 calls for "small attestations" and "chains of cryptographic hashes" linking actions but provides no concrete schema, ordering, or commitment construction.
- **Revocation is left as an endpoint URL.** No on-chain revocation registry, no Merkle accumulator, no CRL design.
- **Inter-agent / multi-agent trust is sketched, not built.** Section "Inter-agent scoping" describes Alice→Bob credential propagation in prose.
- **Standardization is named as future work.** Conclusion: "standardization for agent identity, delegation, and permissions is needed for broader adoption."
- **W3C VC-based delegation is left as future work.** §"Using verifiable credentials as an alternative" explicitly punts on formalization.
- **NL-to-policy translation correctness** is flagged as unsolved (§"Limitations of natural language scoping").
- **PRAG private DB construction** assumes data owners pre-shared shares "at some point in the past" — bootstrapping is out of scope.
- **ORAM for TEE-based RAG** is "considered future work".
- **Confidential GPU inference attestation** is described conceptually but not implemented in the thesis work (H100 noted as enabling tech, not built-on).

**The GLYPH gap, restated**: GLYPH adds a Solana on-chain verifier, deterministic canonicalization, replay protection, on-chain revocation, and an action-transcript commitment scheme for agent actions — all of which the thesis names as motivating but does not specify or implement.

---

## 7. Architecture diagrams (referenced figures)

- **Figure (Ch 4 unnumbered, `authenticated-delegation.tex` line 38, `figs/Overview.pdf`)** — Conceptual overview of a verifiable delegation credential: AI system identity + properties, delegated permissions with contextual scope, user metadata, cryptographic signatures, with the credential mediating agent ↔ third-party-service interactions.
- **Figure `OIDC-AI` (`authenticated-delegation.tex` line 225)** — OIDC + UMA flow diagram: human user (Client) ↔ OP (AS) for steps 1-2; user registers Agent (3); OAuth/UMA issues delegation token to AI Agent₁..Agentₙ acting as RSes (4).
- **Figure (Ch 4 unnumbered, `figs/PCandAuthDel.pdf`)** — Combination of personhood-credential verification with authenticated delegation: human-only spaces remain protected while delegated agents are permitted via PHC-anchored delegation.
- **Figure `fig:exec_summary` (`phc.tex`, `figs/PHC-Figure_Exec_Summary.pdf`)** — Executive summary of the PHC paper: AI risks → indistinguishability + scalability → PHCs as countermeasure.
- **Figure (Ch 2 verifyevals, `figs/verifyevals/high_level_frame.pdf`)** — High-level system motivation; ezkl as the flexible proving backend over arbitrary ML models.
- **Figure `fig:fullsystem` (`verifyevals.tex`, `figs/verifyevals/zkbc_diagram.png`)** — Verifiable-eval pipeline: ONNX → setup → $(pk, vk)$ → per-inference proofs $\pi$ → aggregated attestation → later inference checked against $H(W)$.
- **Figure `fig:scaling` (`verifyevals.tex`, `figs/verifyevals/model_size_archon_may17th.pdf`)** — Proof time and RAM vs constraint count for MLP/CNN/Attn; near-linear in operations, not parameters.
- **Figure `c2:fig:partial-zk` (`partialzk.tex`, `figs/verifyevals/LoraFT.pdf`)** — Three fine-tuning topologies and which weights need to enter the ZK circuit: full $Wx$ vs LoRA $BAx$ vs head $HWx$.
- **Figure `fig:diagram_3services` (`zktax.tex`, `figs/zktax/diagram_3services.png`)** — Three-service redact-and-prove flow: TDS signs → user redacts/proves → verifier checks with TDS public key.
- **Figure `fig:pragdiagram` (`PRAG.tex`, `figs/PRAG_IVF_diagram.pdf`)** — Distributed secret-shared inverted-file index across servers; client sends shares, servers compute MPC top-k, return shares of top-k document tokens.
- **Figure `fig:agent-workflow` (`chapter-5.tex`, `./ai-system-parts.pdf`)** — End-to-end AI system parts map: data provenance (zkTax) → training/eval (verifyevals/partialzk) → runtime privacy (PRAG/TEE-RAG) → agent delegation (auth-deleg + PHCs) → audit chain.
