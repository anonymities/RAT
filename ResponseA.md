## **Review A**:

#### ***Q1: Can the authors clarify the prompt design by showing all prompts/templates used?*** 

**A1**: Thank you for the insightful question! To accomplish the following five sequential tasks: (1) generating code for crawling GitHub issues, (2) analyzing whether the issues involve bugs related to certificate parsing or validation, (3) generating mutation directives from the analysis results to guide CRL mutations, (4) normalizing the mutated CRLs produced by applying the mutation directives into a canonical format, and (6) evaluating whether the normalized CRLs comply with the RFC 5280 specification, we designed five corresponding prompt sections, each instructing the LLM to perform one specific task. 

Due to the word limit, all prompts have been saved in the `prompts.md` file (https://github.com/anonymities/RAT/blob/main/prompts.md), and the link has been added to the revised manuscript.

#### ***Q2: Can the authors clarify the technical details in the experiments?***

**A2**: As requested in the second detailed comment, we clarify technical details as follows.
* ***The definition and example of "Mutation Directives".***

    A mutation directive is a structured command that instructs a testing system which fields in a CRL to modify and what values to use, in order to probe for bugs in CRL parsers. These directives are expressed in JavaScript Object Notation (JSON) format.

    Here is an example.

        {
            "num":"opensslxxxxx",
            "issue":{
                    "create authorityKeyIdentifier":{
                        "KeyIdentifier":""
                     },
                    "issuer":"C=XX, O=XX-CA, OU=Root CA, CN=XXCA Global Root CA"
            }
        },

     
* ***Prompt design.*** 
    
    Please refer to A1 and the associated URL.
     
* ***Low-level details like extracted data, mutation directives, mutaiton operators, and the data processing logic.***
     
    RAT leverages the LLM to extract concrete erroneous values from GitHub Issues and generate targeted mutation directives (e.g., `{"thisUpdate": "invalid_time"}`). These directives drive an ASN.1-aware mutation engine that applies three atomic mutation operators: value-level mutation, which directly injects the extracted field values; encoding-level mutation, which alters ASN.1 encodings by switching tag types in ways that conform to or deliberately violate RFC specifications; and structure-level mutation, which manipulates the CRL’s hierarchical layout—for instance, by duplicating extensions or inserting malformed nested sequences. To handle the heterogeneous outputs such as varying field names or error message formats, RAT uses the LLM to normalize these results into a consistent representation. It then constructs the parsing status vector and the path-content vector, and compares them across parsers to precisely identify discrepancies in both parsing behavior and interpreted content. 

* ***Why was RAT configured to analyze 3,523 GitHub issues in 1 hour and 56 minutes?***

    Thank you for the insightful question. To clarify, RAT was not explicitly configured to spend 1 hour and 56 minutes analyzing the 3,523 GitHub issues. Rather, this duration reflects the actual end-to-end runtime required for RAT to automatically process all 3,523 issues—including LLM-based analysis, extraction of bug-relevant values, and generation of mutation directives—on our experimental setup. The time is a measured outcome of the system’s current implementation and workload, not a pre-set timeout or scheduling constraint. We included this timing information to provide transparency about the practical efficiency of our approach.
     

* ***How were the GitHub issues mined? What is the prompt? What is the scope of mining? Why did LLMs end up with finding 3,523 GitHub issues?*** 

    Thank you for the thoughtful questions. We leveraged Prompt Section I to instruct LLM to generate code for crawling 5 major TLS-related repositories up to January 2025. The retrieved issues were analyzed by the LLM using Prompt Section II to filter those associated with certificate parsing or validation. Thus, 3,523 GitHub issues are ratained. Prompt Sections I and II are in https://github.com/anonymities/RAT/blob/main/prompts.md.

* ***Why was AFL++ configured to execute 42.6 hours? What will happen if these tools get executed for the same amount of time? What will happen if both tools get executed for a longer time?***

     To maximize AFL++’s effectiveness, we ran it until no new discrepancies were found for one consecutive hour. If both tools are constrained to RAT’s runtime, AFL++ finds fewer discrepancies. If both run for AFL++’s runtime (with RAT repeated as needed), or even longer, the number of discrepancies detected by either tool does not increase.

* ***Do the discrepancies in Table 2 overlap significantly or is there any overlap at all? How about the severity of these discrepancies? Did the developers of CRL parsers care about these discrepancies or fix the corresponding bugs? If so, how many were confirmed and addressed?***

     Among the discrepancies in Table 2, 10 overlap. Several discrepancies are security-critical. For example, OpenSSL’s incorrect handling of non-ASCII characters in authorityCertIssuer, leads to validation bypasses. Developers cared, confirmed and fixed 13 discrepancies. 

Thank you for the suggestion! We have incorporated the missing technical details into the revised manuscript.

#### ***Response to Detailed Comments*** 
* ***C3: Section 2 can be shortened considerably. Section 4.5 can be also refined and shortened.***

    We appreciate your suggestion. In the revised manuscript, we have significantly condensed Section 2. Similarly, Section 4.5 has been streamlined.
  
We appreciate your guidance in helping us improve the manuscript!

