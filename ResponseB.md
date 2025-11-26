## **Review B**:

#### ***Q1: What kind of problems the approach is unable or unlikely to capture?***

**A1**:
    RAT is unlikely to capture three kinds of problems: (1) It cannot detect novel bugs that lack prior GitHub issue reports, as its mutation directives rely on LLM extraction from historical bug descriptions; (2) It only targets parsing logic, missing non-parsing-related bugs (e.g., memory leakage); and (3) It struggles to trigger bugs requiring complex environments such as multi-component interactions.

 

#### ***Q2: Does RAT's targeted approach justifies its complexity and resource use?***

**A2**: 
Yes. RAT’s targeted design enables it to efficiently uncover security-critical parsing discrepancies that generic fuzzers miss, as evidenced by 13 confirmed fixes. Its LLM-driven mutation reduces search space dramatically, achieving saturation in under 2 hours, whereas AFL++ requires significantly more time (42.6 hours) without finding additional discrepancies. RAT's structured complexity enables reuse for testing other cryptographic parsers, making it a generalizable framework rather than a one-off tool. Thus, the modest added complexity and resource use are justified by both effectiveness and efficiency.



#### ***Q3: How exactly using LLMs for structured information extraction from bug reports is novel or is it merely an application of existing techniques?*** 

**A3**: 
Thank you for this important question. The novelty of RAT lies in how we integrate LLMs into a security testing pipeline:
(1) Task-specific prompt engineering. We design a multi-stage prompting strategy that transforms unstructured GitHub issues into executable mutation directives instead of just generic summaries or labels. This bridges natural-language bug reports and concrete, ASN.1-aware test inputs.
(2) Closed-loop synergy with formal mutation. The extracted directives directly drive an RFC- and ASN.1-aware mutation engine, enabling semantics-guided differential testing. To our knowledge, this is the first framework that systematically converts historical parsing bugs into structured, replayable CRL mutations via LLMs.
(3) Domain adaptation without fine-tuning. We achieve high-fidelity extraction using only carefully crafted prompts without model fine-tuning or labeled training data, making the approach lightweight and portable across cryptographic parsers.
Thus, while LLMs are a known tool, their use here as a programmable bridge between real-world bug reports and protocol testing represents a novel pattern with demonstrated impact (13 confirmed fixes).


#### ***Q4: There appears to be ambiguity regarding how issues were selected for inclusion in the test corpus.*** 

**A4**:
Thank you for pointing this out. We clarify that the issues were selected through two stages:
(1) Initial collection. We used LLM-generated code to crawl issues from five major TLS-related repositories up to January 2025. and 
(2) Relevance filtering. Each issue was analyzed by the LLM via Prompt Section II to determine if it described a certificate/CRL parsing or validation bug; only those labeled “relevant” were retained. This yielded 3,523 issues selected.

#### ***Q5: Are there new classes of bugs discovered?****

**A5**:
Thank you. RAT did not discover fundamentally new classes of bugs, but it revealed previously unknown, security-relevant differential behaviors in CRL parsing such as validation bypasses due to non-ASCII authorityCertIssuer handling that constitute new bug instances and scenarios. Thirteen have been confirmed and fixed, demonstrating their practical impact. 


#### ***Response to Detailed Comments***
* ***C1: How  was the initial set of issues obtained? Why is it a representative set?****

    Regarding the first question, please see our detailed response to Question 4 (A4) for how the initial issue set was collected.
    This set is representative not only because it spans 15 years of real-world bugs from widely deployed TLS libraries, but also because certificates and CRLs share highly similar ASN.1 structures—meaning historical certificate-parsing bugs are strongly indicative of potential flaws in CRL parsers. This structural homology makes them highly effective seeds for mutation-based testing, as confirmed by 13 developer-validated fixes.
    
* ***C2: It was not entirely clear to me if the effort to create the specific domain-specific testing framework was worth it as a generic fuzzer seemed to do a good job and computation devoted to testing seems to be a minor expense. LLMs, in fact, may consume more computational time, but since it is provided as a service authors appear to ignore it.***
    Thank you for the comment. RAT outperforms generic fuzzers not in raw bug count, but in quality: it finds more semantic discrepancies unreachable via fuzzers' byte flips. RAT's 2-hour runtime includes all LLM usage, yielding >20× speedup compared to AFL++'s 42.6 hours. While LLMs have high training costs, these are amortized across users; the marginal cost here is low and justified by 13 confirmed fixes. Thus, RAT delivers better return on investment for structured object testing.

* ***C3: The engineering solutions in how LLMs are used do not appear innovative.***

    Thank you. While our use of LLMs builds on existing techniques, RAT’s novelty lies in the end-to-end pipeline that transforms **unstructured bug reports** into **structured mutation directives** and then into **ASN.1-aware test cases**. By leveraging LLMs, RAT uniquely bridges natural-language knowledge from real-world issues to binary-level, semantics-preserving fuzzing, addressing a gap generic code-generation approaches cannot solve. It’s a new workflow for protocol-aware testing.

We appreciate the reviewer’s questions and comments, which helped us better articulate RAT’s novelty in the revised manuscript.

