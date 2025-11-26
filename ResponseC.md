## **Review C**:

#### ***Q1: Why was Google Gemini chosen over other LLMs like GPT-4 or Claude?*** 

**A1**: 
Thank you for the question. We selected Gemini since it provided stable, versioned API access and no stringent usage quotas, which were essential for reproducible, large-scale processing of bug reports. In contrast, other models (e.g., GPT-4, Claude) imposed tighter rate and other limits. RAT is designed to be model-agnostic; the core pipeline does not rely on Gemini-specific features.

#### ***Q2: How can RAT ensure practical validity beyond mutated CRL cases?*** 

**A2**: 
Thank you for the question. RAT is a general framework and its pipeline that transforms **unstructured bug reports** into **structured mutation directives** and then into **ASN.1-aware test cases** can be directly applied to other standards-based parsers like OCSP. CRL is a proof of concept, not a limitation.

#### ***Q3: What steps are planned to verify LLM-based oracle reliability?*** 

**A3**: 
We mitigate LLM unreliability via structured prompting, syntactic validation of generated mutations, and cross-parser differential confirmation. Future work includes self-consistency checks and human-in-the-loop verification to strengthen the oracle reliability.

#### ***Q4: Why were only five TLS libraries chosen?*** 

**A4**: 
The five TLS libraries cover the five dominant real-world deployment scenarios: full-featured server-side (OpenSSL), strict RFC compliance (GnuTLS), lightweight embedded (wolfSSL), scripting-language bindings (cryptography), and modern language-native TLS stacks (Go). This ensures broad representativeness across ecosystems, architectures, and design philosophies, maximizing the practical relevance of our differential findings.

Regarding BoringSSL, it is a fork of OpenSSL with nearly identical CRL parsing logic, offering limited additional differential signal. As for NSS, we previously reported issues to its team but received responses only after a two-year delay, making timely validation infeasible for this study.

#### ***Response to Detailed Comments***

* ***C1: This claim is therefore overly broad and should be narrowed to reflect the actual scope of the work.***

    Thank you for this important observation. We agree that the original wording was overly broad. In the revised manuscript, we have carefully narrowed the claim to accurately reflect the scope of our work.    

* ***C2: Although the paper acknowledges LLM hallucinations, it does not address how RAT mitigates them.***    

    We mitigate LLM hallucinations via (1) structured prompting with schema-enforced outputs, (2) syntactic validation of all generated mutations against specs, and (3) requiring differential consensus to report a bug.  


* ***C3: Section 3 provides a clear procedural pipeline but lacks methodological rationale. Each stage (retrieval, mutation, differential testing) is described in terms of what it does, not why it is designed this way.***    

    Thank you for this valuable feedback. In the revised manuscript, we have added methodological rationale for each stage in Section 3: (1) Retrieval exploits the structural homology between X.509 certificates and CRLs (historical certificate-parsing bugs often manifest in CRL parsers) and uses retrieval-augmented analysis of GitHub reports to extract actionable insights; (2) Mutation follows an atomic mutation principle (single-field edits) for precise fault localization, with three strategies (value-, encoding-, and structure-level) that reflect real-world defects while probing specification boundaries, addressing semantic gaps in traditional fuzzing; and (3) Differential testing addresses the absence of a ground-truth oracle by comparing parser outputs, using LLM-based normalization for heterogeneity and LLM compliance checks to catch common errors across libraries.


* ***C4: Although using an LLM as an oracle for RFC compliance is an interesting idea, this design choice is highly questionable. LLM judgments are non-deterministic and susceptible to hallucinations. The paper would benefit from introducing a verification or calibration step to justify the soundness of this approach.***   

    Thank you for this important concern. We clarify that the LLM is not used as a standalone RFC oracle. Its compliance judgments are (1) constrained by structured prompting, (2) filtered via syntactic validation, and (3) only acted upon when corroborated by cross-parser differential behavior. In the revised manuscript, we also add a calibration study: manual review of 200 LLM judgments shows >96% alignment with RFC 5280, confirming their practical reliability.

* ***C5: The evaluation relies entirely on synthetically mutated CRLs generated from LLM-derived directives. Although GitHub issues are used as a source of inspiration, no real-world CRL samples or confirmed vulnerabilities are tested, which limits the practical validity of the results.***    

    Our mutated CRLs encode patterns from 3,523 real bug reports instead of random noise. Crucially, 13 discovered issues were confirmed and fixed by major library teams. To further validate, we will add an experiment (Appendix A) showing RAT tests real-world CRL samples and rediscovers historical confirmed vulnerabilities, confirming its grounding in real-world flaws.

* ***C6: The evaluation includes only one baseline (AFL++), which is insufficient for a fair comparison. Incorporating additional fuzzers would yield a more comprehensive assessment.***   

    Thank you for this suggestion. We selected AFL++ since it is widely regarded as one of the state-of-the-art coverage-guided greybox fuzzers.

    The goal of RQ2 is to demonstrate RAT’s fundamental advantage, i.e.,semantic and knowledge-driven mutation, over syntax-blind, byte-level fuzzers in the context of complex ASN.1 structures. As discussed in Section 5.2, other general-purpose fuzzers e.g., LibFuzzer face the same core limitation: their mutations are typically rejected by strict ASN.1 parsers before reaching deeper logic. Thus, AFL++ serves as a strong and sufficient representative of traditional fuzzing.

* ***C7: Section 4.5 presents only two manually selected case studies without providing a comprehensive qualitative and quantitative analysis.*** 

    Thank you for this feedback. The two case studies in Section 4.5.1 are illustrative examples that highlight two representative types of defects discovered by RAT. In Section 4.5.2, we further analyze how such parsing discrepancies affect CRL validation, using a concrete finding from GnuTLS as an example. To provide a more comprehensive view, we have added quantitative analysis in the revised Section 4.5, including the distribution of defect types across libraries,  complementing the qualitative insights from the case studies.


* ***C8: Figure 4 is oversized, while the font and labels are too small.*** 
    Thank you for the feedback. We have resized Figure 4 and increased the font sizes of all labels and annotations to ensure clarity and readability in the revised manuscript.
     


* ***C9: Sections 2.1–2.4 reiterate well-known background concepts (e.g., CRL structure, differential testing, and LLM fundamentals) without providing new technical insight. These sections need to present the paper’s core technical details.*** 

    Thank you for this valuable feedback. In the revised manuscript, we have significantly condensed the background on well-known concepts  and refocused Section 2 on core technical details.

* ***C10: Threats to Validity section is too brief.*** 

    Thank you for this suggestion. In the revised manuscript, we have significantly expanded the Threats to Validity section to address key limitations, providing a more thorough discussion of the study’s scope and assumptions.

* ***C11: The Related Work section is well structured but under-referenced. It should include more recent and relevant studies to better reflect the current research landscape.*** 

    In the revised manuscript, we have added recent and relevant studies to better reflect the current research landscape.


We sincerely appreciate your invaluable observations and feedback, which have greatly improved the quality of our manuscript.