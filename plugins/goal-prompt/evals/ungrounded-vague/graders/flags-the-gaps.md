---
type: llm
weight: 1
---

An unjudgeable goal handed back without a warning strands the user. The answer must tell them what to
supply.

Pass only if, outside the fenced `/goal` block, the response explicitly tells the user what is missing
before this goal is usable, covering at least two of: (a) which metric and threshold define "faster",
(b) how the improvement would be verified (benchmark, command, measurement), (c) a stop bound. A "Missing:"
list, questions to the user, or equivalent prose all count.

Fail if the response presents the goal as ready to use with no statement of what is missing, or buries the
gaps as optional polish ("you could also add metrics") rather than required information.
