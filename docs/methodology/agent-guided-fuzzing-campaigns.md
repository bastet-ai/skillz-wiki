# Agent-guided fuzzing campaigns

**Date**: 2026-07-02; updated 2026-08-26

**Sources**: Trail of Bits, *Field reports from Patch the Planet*, *How we use /goal to find bugs in Patch the Planet*, and *VMs won't contain cyber-capable agents*

**Status**: Durable offensive operator workflow

---

## Core lesson

Frontier coding agents can now build useful fuzzing campaigns without being handed every harness step. The operator value is not “ask an agent to fuzz it” — it is giving the agent a scoped target, hard validity rules, observable sanitizer output, and a replayable evidence standard.

Use this workflow for authorized source reviews where parser, compression, archive, media, protocol, model, or file-format code exposes attacker-controlled input.

---

## When to use it

Good targets:

- compression, archive, codec, image, document, model, chemistry, geospatial, and serialization libraries
- network protocol parsers and stateful stream decoders
- CLI tools that ingest untrusted files or package metadata
- compatibility layers with compile-time flags, alternate backends, or legacy parser modes
- codebases with existing unit tests but narrow or shallow fuzz coverage

Avoid using agent-generated fuzzing as evidence when:

- you cannot build the target reproducibly
- crashes require impossible API states or caller misuse
- the harness never reaches meaningful parser/state branches
- you cannot preserve corpus, build flags, sanitizer output, and minimized inputs for replay

---

## Campaign setup

Give the agent a narrow objective and force it to prove reachability.

```text
Goal: build an authorized fuzzing campaign for <target component>.
Find only bugs reachable through documented/public or attacker-controlled input paths.
Use ASan/UBSan or the strongest available equivalent.
Prefer existing edge-case tests and fixtures as seeds.
Explore alternate build variants and feature flags that change parser behavior.
Reject crashes caused by invalid harness states or impossible caller misuse.
Preserve every command, corpus seed, minimized reproducer, and sanitizer trace.
```

### Define success before choosing the path

For an autonomous run, write the goal as a testable completion contract rather than a recipe. Include:

- one vulnerability outcome and the exact threat model it must satisfy;
- attacker-controlled inputs and normal/default configurations that count;
- local control, privileges, configuration changes, or prior execution that must **not** be assumed;
- a duplicate-check requirement;
- the minimum safe proof and evidence bundle;
- an explicit statement that “no bug found,” a crash without reachability, and a known issue do not satisfy the goal;
- a stopping condition: one validated, previously unreported candidate.

Do not prescribe a new harness, a specific code path, or an exact root cause unless that is the experiment. “Use fuzzing” leaves the agent free to reuse a better existing harness. For variant analysis, a one-sentence vulnerability class can be more productive than handing the agent the complete original backtrace.

Have a separate agent draft and challenge the goal before the campaign:

```text
Read THREAT_MODEL.md and the repository's build/test guidance.
Draft one goal for finding one previously unreported <impact> issue reachable by
<remote/file/API attacker> under <normal configuration>.

List the shortcuts a future agent could use to satisfy the wording without finding
a valid vulnerability: impossible attacker control, test-only APIs, known issues,
unreplayed crashes, missing default reachability, or evidence-only claims.
Revise the goal to close those exits without prescribing the search path.
```

Treat source-reading and coverage metrics as campaign telemetry, not as substitutes for a vulnerability. If available, record which files or lines the agent actually inspected so a confident result cannot rest on a narrow code sample.

### One outcome per agent

Do not ask one session to maximize code coverage and find a vulnerability. Those are competing objectives.

1. Run a **surface-mapping session** that inventories the repository and ranks a small number of attacker-reachable areas.
2. Assign one independent vulnerability-finding session to each area.
3. Add one open-ended session for surfaces the partitioning may have missed.
4. Run coverage analysis separately and use its gaps to seed another round; do not redefine a vulnerability run as “done” because coverage increased.
5. For variant analysis, spawn one session per source issue or bug class rather than asking one session to process the entire history.

Each worker should receive the same threat model and report schema, but only one outcome. Keep run IDs, repository commits, inputs, and artifacts isolated so results can be replayed independently.

PortSwigger's October 6 "The model isn't cooperating" eval generalized this: open-ended research prompts ("explore other threats arising from the same root cause") cause models to silently steer toward low-impact, easy-to-observe outcomes without refusing — intelligence rank did not predict research score, and impact steering helped models unevenly (Opus 4.6 responded best). See the "October 6 follow-up" section of the [HTTP desync research campaigns](http-desync-research-campaigns.md) page for the trace-review, scope-narrowing, and per-model steering-response rules before adding agents or budget to a stalled campaign.

### Gate variant-analysis inputs and outputs

Historical critical bugs are useful seeds only after a gate confirms they represent a real security boundary for the current threat model. Route each seed to:

```text
skip        source issue is not security-relevant or is outside scope
no_variant  valid vulnerability class, but no distinct reachable variant reproduced
candidate   distinct behavior with a safe reproducer and plausible security impact
```

Pass candidates through two independent reviews: one for threat-model and impact validity, and another focused on clean-checkout PoC replay. Then perform a human duplicate search against local findings, upstream issues, pull requests, release notes, and advisories before submission. Model agreement is triage evidence, not confirmation.

For C/C++ targets, start with a matrix like:

```text
build: default + ASan + UBSan
build: strict parser flags + ASan + UBSan
build: legacy/compatibility flags + ASan + UBSan
entrypoints: public parse/decode/decompress APIs
seeds: unit-test fixtures, regression files, boundary cases, tiny valid samples
oracle: sanitizer crash, invariant assertion, differential parse result, timeout only when security-relevant
```

---

## Harness strategy

Tell the agent to build breadth first, then deepen where coverage moves.

1. **Inventory reachable entrypoints**
   - public API functions
   - CLI file-ingestion paths
   - streaming/state-machine APIs
   - compatibility wrappers and contrib modules

2. **Seed from real behavior**
   - existing unit tests
   - regression files
   - tiny valid files/messages
   - edge cases already documented by maintainers

3. **Vary the build**
   - sanitizer builds: ASan, UBSan, MSan where practical
   - strict/legacy feature flags
   - optional parser backends
   - platform-specific branches if the target is portable

4. **Measure reachability**
   - require coverage growth beyond argument validation
   - log functions and branches reached by each harness
   - discard harnesses that only exercise invalid setup paths

5. **Minimize and classify**
   - minimize crashers
   - replay under the exact build
   - determine whether a real caller can create the vulnerable state
   - separate parser bugs from harness bugs

---

## Validity rules for agent output

A finding is reportable only when the campaign can answer these questions:

- What attacker-controlled input reaches the failing code?
- Which public API, CLI command, service route, or file-ingestion path exercises it?
- Does the minimized input work from a clean checkout and documented build?
- Does the crash depend on an impossible caller state, null callback, internal-only API misuse, or test-only configuration?
- Is there a patched or negative-control build showing the behavior disappears?
- Are sanitizer traces, build flags, corpus seed, and reproducer small enough for a maintainer to replay?

If the agent cannot answer those, keep fuzzing but do not publish or report the crash as a vulnerability.

---

## Operator prompt pattern

Use a prompt like this inside a local lab or authorized code-review environment:

```text
You are auditing <repo> for reachable parser/memory-safety bugs.
Work only inside this checkout and temporary build directories.
Do not run network commands except package installs already required by the project.

Tasks:
1. Identify attacker-controlled parsing/decode/decompress entrypoints.
2. Build sanitizer-enabled variants and record exact commands.
3. Create fuzz harnesses for the top entrypoints.
4. Seed from existing tests and minimal valid files.
5. Run short smoke campaigns, then expand the most promising harnesses.
6. Minimize any crashers and prove replay from a clean build.
7. Reject findings that require impossible public API states.
8. Produce an evidence bundle with commands, flags, corpus seeds, minimized inputs, and sanitizer output.
```

For a goal-driven discovery run, keep the search path open while making the acceptance boundary strict:

```text
Audit <repo> at <commit> and find exactly one previously unreported <impact>
vulnerability reachable in normal/default use by <attacker model> through
<allowed attacker-controlled inputs>.

First create a concise threat model and rank attacker-reachable trust boundaries.
Do not assume control of local configuration, command-line arguments, environment,
plugins, source, credentials, administrator privileges, or prior code execution.
Reject candidates that need those preconditions.

Before accepting a candidate, search local findings and current upstream issues,
pull requests, releases, and advisories for duplicates. Produce a minimal inert or
sanitizer-backed proof, replay it from a clean checkout, and save the threat path,
commands, artifacts, negative controls, and exact result under <output directory>.
The following do not satisfy the goal: no finding, an untriaged crash, a known
issue, or an unreplayed hypothesis. Stop after one valid candidate.
```

---

## Evidence bundle

Capture these artifacts before reporting:

```text
repo commit / release
compiler and sanitizer versions
all build flags and feature flags
harness source files
seed corpus source and hashes
fuzzer command lines and runtime limits
coverage summary or reached-function list
minimized reproducer files
sanitizer trace
negative-control or patched-version result
reachability explanation from real input to failing code
```

Keep inputs synthetic and minimal. Do not include customer data, proprietary corpora, production crash dumps, credentials, model weights, private documents, or unrelated files from the target environment.

---

## Reporting heuristic

High-signal reports state what the agent proved and what it rejected:

- “Reachable through `tool parse <file>` with this minimized file.”
- “Reproduces under default and strict builds; fixed in patched commit.”
- “Not dependent on a null callback, mocked allocator, or invalid internal state.”
- “The harness reaches the same state using public streaming APIs.”

Low-signal reports to avoid:

- “The fuzzer crashed” without reachability.
- “ASan found a bug” without a clean reproducer.
- “The agent says this is exploitable” without a public input path.
- Crashes that require harness-only object layouts or impossible caller behavior.

---

## Safety boundaries

- Run campaigns only on code you own or are authorized to test.
- Keep fuzzing in disposable lab containers or worktrees.
- Do not fuzz production services or shared developer machines.
- Do not use live user files as seed corpora.
- Do not publish weaponized exploit chains before coordinated disclosure.

---

## August 26 follow-up: agent-driven VM-escape 0-day discovery

**Source:** Trail of Bits, [VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/).

This report extends the campaign workflow from "find one bug in a parser" to a
**containment-escape goal**: an agent starts outside a QEMU/KVM VM, gets SSH in,
and must read a flag on the host — i.e. it must escape the VM. The agent ran for
roughly 12 hours, backtracked, wrote its own oracles, and chained several 0-days
to get a host primitive. Treat it as the durable template for any authorized
red-team / sandbox-escape scenario where the target boundary is a VM, container,
or agent sandbox rather than a single component.

### The reusable operator lessons

1. **Model the sandbox boundary as the target, not the code.** The
   "attacker-controlled input" here is the entire shared surface between the
   sandbox and the host: the virtualization stack (QEMU + KVM + the specific
   feature flags you enabled), the guest network backend (libslirp, virtio-net,
   user-mode networking), host services the guest can reach (CUPS, SSH, display
   listeners), and the host kernel itself. Inventory each one before you start.

2. **Distribution backport lag is attack surface.** The agent's first two
   escapes both came from bugs that were *fixed upstream but not present in the
   distro's shipped package* — one a CVE that never reached `oldstable`, one a
   plain fix commit with **no CVE assigned** that the agent combined with a real
   CVE to make an arbitrary host memory read/write. So the recon step is a
   three-way diff, not a CVE lookup:
   ```text
   for each component on the host:
     - what is the installed distro version?
     - what does the latest upstream tag/commit change in that component?
     - which of those changes are security fixes (CVE or no-CVE)?
     - is the no-CVE fix reachable/chainable with the distro's exposed surface?
   ```

3. **Feature flags expand the surface even when "unused."** `-display none`,
   `mitigations=off`, VAPIC ROM aliasing, and SMRAM each opened a distinct path.
   The operator should enumerate every enabled device/feature and treat "we don't
   use the display" as a note that a display-renderer bug is *not* currently
   reachable — not as a reason to skip it. Record the precondition that blocks
   each candidate so the report states exactly what configuration makes it live.

4. **Long-horizon persistence is the campaign property.** What made this run
   different from a short fuzz session: the agent kept a research ledger,
   backtracked across dead ends over many sub-agent invocations, wrote minimal
   oracles to test hypotheses, and stopped only on a *reliable* exploit. The
   "one outcome per agent" rule still applies — the goal was "read the flag",
   not "maximize coverage". Coverage/telemetry and the escape primitive are
   separate tracks.

5. **Chain to a primitive, then stop at the primitive.** The final chain
   composed independent bugs (SMRAM/SMM exposure, a KVM shadow-page desync, a
   KVM paging stale-role bug, a libslirp ICMP IHL reflection overflow) into one
   host write. The evidence standard is the *primitive* (host read/write, SMM
   execution), not the flag. Report the chain, the per-link proof, and which
   link is the 0-day.

### Goal contract for a sandbox-escape run

```text
Goal: escape the sandbox and read a marker/flag on the host.
Threat model: you start <outside/inside> the sandbox with <ssh/network/none>;
you may not read the flag without crossing the sandbox->host boundary.
Inventory the full shared surface (virtualizer, guest-net backend, host kernel,
reachable host services, enabled devices/feature flags) before choosing a path.
For each candidate, do the three-way diff: installed version vs upstream fix vs
CVE/no-CVE status, and record the precondition that makes it reachable.
Build a reliable primitive (host read/write / privilege / SMM), not a crash.
Keep a research ledger; backtrack; write oracles; minimize.
Reject escapes that require impossible host state or that only work with a
feature you disabled. Produce the chain, per-link proof, 0-day vs known split,
and negative controls. Stop at the primitive.
```

### Evidence bundle additions

- the exact virtualizer/feature-flag build and the host-kernel commit;
- the three-way diff table (installed / upstream / CVE-or-no-CVE) per component;
- per-link proof for each bug in the chain and which links are 0-days;
- the precondition (feature flag / mitigation state / service) that makes the
  final link reachable;
- a negative control showing the primitive disappears when the flagged feature is
  disabled or the kernel is patched.

### Safety boundaries (escape-specific)

- Run only on a disposable host/VM you control; never on a shared dev box or
  production hypervisor.
- Do not persist, install, or exfiltrate on a live host; the proof is the
  primitive plus the flag read on the lab target.
- Report 0-days through the vendor's coordinated-disclosure channel before
  publishing the chain.
- Keep the research ledger and minimized oracles; they are the replayable
  evidence that separates a validated escape from a lucky crash.

---

## References

- Trail of Bits: [Field reports from Patch the Planet](https://blog.trailofbits.com/2026/07/02/field-reports-from-patch-the-planet/)
- Trail of Bits: [How we use /goal to find bugs in Patch the Planet](https://blog.trailofbits.com/2026/07/28/how-we-use-goal-to-find-bugs-in-patch-the-planet/)
- Trail of Bits: [Introducing Patch the Planet](https://blog.trailofbits.com/2026/06/22/introducing-patch-the-planet/)
- Trail of Bits: [VMs won't contain cyber-capable agents](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)
