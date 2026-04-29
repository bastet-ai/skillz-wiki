# Code Graphs Beat Lists for Security Analysis

**Date**: 2026-04-29  
**Source**: Trail of Bits, *Trailmark turns code into graphs*  
**Status**: Durable guidance

---

## Core lesson

Security analysis gets much better when you reason about the codebase as a graph instead of a list of findings.

Lists are useful for output. Graphs are useful for judgment:

- what reaches untrusted input
- what sits on a privilege boundary
- what has high blast radius
- what paths connect an entrypoint to a sink

Trailmark’s core idea is worth keeping: turn source into a queryable graph, then let analysis ask graph questions instead of reading flat scan output.

---

## Why this matters

Flat lists often hide the real question:

- surviving mutants may be equivalent, dead, or security-relevant
- coverage reports don’t show reachability
- static findings don’t show whether a flaw is actually reachable
- call chains matter more than isolated lines

If you can’t answer “how does input get here?” you probably don’t have enough context yet.

---

## Practical guidance

### 1) Build the graph first

Capture at least:

- functions and classes
- call edges
- entrypoints
- type/semantic metadata
- complexity hotspots

### 2) Ask graph questions

Use the graph to answer:

- callers / callees
- paths between nodes
- taint propagation
- privilege boundaries
- attack-surface enumeration

### 3) Prioritize by reachability

A reachable low-severity bug often matters more than a flashy but dead-code issue.

### 4) Use graphs to triage noise

This is especially useful for:

- mutation testing survivors
- reverse-engineering
- protocol analysis
- large codebases with too many flat findings

### 5) Verify before concluding

Treat graph output as a decision aid, not proof. Confirm the path against runtime behavior or source truth before reporting.

---

## Operational pattern

1. Parse code into a graph.
2. Identify entrypoints and sinks.
3. Query paths and blast radius.
4. Triage findings by reachability and impact.
5. Validate the highest-value paths first.

---

## References

- Trail of Bits: <https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/>
- Trailmark: <https://github.com/trailofbits/trailmark>
