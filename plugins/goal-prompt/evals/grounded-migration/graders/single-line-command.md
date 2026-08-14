---
type: llm
weight: 1
---

The deliverable is one copy-paste-ready command.

Pass only if the response's final answer contains exactly one fenced code block whose entire content is a
single line starting with `/goal `, and the response adds no second candidate command. Prose before the
block or a short list of open questions after it does not fail this grader.

Fail if:
- the goal text spans multiple lines inside the block (bullet points, indentation, blank lines);
- there is no fenced block, or the `/goal` command appears only inline in prose;
- more than one `/goal` variant is offered, leaving the user to choose;
- the block's line is over 4,000 characters.
