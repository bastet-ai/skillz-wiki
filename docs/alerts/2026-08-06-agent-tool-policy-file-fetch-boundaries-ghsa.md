---
title: Agent control-plane, tool-policy, file, and fetch authority boundaries
---

# Agent control-plane, tool-policy, file, and fetch authority boundaries

Twenty-two August 6 records, three August 7 Nanobot follow-ups, eleven August 8 MCP-wrapper records, twenty-four August 9 agent/MCP follow-ups, and six August 10 MCP follow-ups expose a reusable agent-platform testing pattern: an early mode, deny-list, approval, path, environment, argument, or URL decision is not authoritative when a later route, capability wrapper, alternate command handler, recursive scanner, login shell, file sink, process wrapper, or connector sees richer input.

Source records:

- NanoClaw `send_file` local-read boundary: [GHSA-q94p-g4rh-r9rf](https://github.com/advisories/GHSA-q94p-g4rh-r9rf) and [project issue #2760](https://github.com/nanocoai/nanoclaw/issues/2760);
- LettaBot shared-mode management routes: [GHSA-c8v3-2w4m-9q57](https://github.com/advisories/GHSA-c8v3-2w4m-9q57) and the [disclosure record](https://gist.github.com/YLChen-007/2ba2e586f3d16cb368c8dcd6ef680178);
- Hermes Agent memory-tool deny-policy bypass: [GHSA-6rr9-mpp7-j4mp](https://github.com/advisories/GHSA-6rr9-mpp7-j4mp), [project issue #46171](https://github.com/NousResearch/hermes-agent/issues/46171), and [proposed fix #46185](https://github.com/NousResearch/hermes-agent/pull/46185);
- IronClaw shell approval parser differential: [GHSA-cw23-qwr7-c655](https://github.com/advisories/GHSA-cw23-qwr7-c655), [project issue #4861](https://github.com/nearai/ironclaw/issues/4861), and [merged fix #4869](https://github.com/nearai/ironclaw/pull/4869);
- super-agent-party `extension_proxy` outbound-fetch boundary: [GHSA-m39w-xf3h-v4h2](https://github.com/advisories/GHSA-m39w-xf3h-v4h2) and the [disclosure record](https://gist.github.com/YLChen-007/2f12ffb785d975b46b73896c0fb8cb5d); and
- super-agent-party manual `get_file_content` dispatch: [GHSA-fvhg-m33v-6wqx](https://github.com/advisories/GHSA-fvhg-m33v-6wqx) and the [disclosure record](https://gist.github.com/YLChen-007/479bfabb441bd6cc5337db910b004841);
- Mercury Agent shell redirection, alternate `/bg` command, and restricted-child tool-surface records: [GHSA-ccg4-hv3q-9622](https://github.com/advisories/GHSA-ccg4-hv3q-9622), [issue #72](https://github.com/cosmicstack-labs/mercury-agent/issues/72), [GHSA-9hrj-55h5-5mr2](https://github.com/advisories/GHSA-9hrj-55h5-5mr2), [issue #73](https://github.com/cosmicstack-labs/mercury-agent/issues/73), [GHSA-7hmv-r6w5-pr73](https://github.com/advisories/GHSA-7hmv-r6w5-pr73), and [issue #74](https://github.com/cosmicstack-labs/mercury-agent/issues/74);
- CowAgent Self-Evolution MCP tool re-injection: [GHSA-wjcq-xp37-c947](https://github.com/advisories/GHSA-wjcq-xp37-c947) and [issue #2904](https://github.com/zhayujie/CowAgent/issues/2904);
- LobsterAI message-derived artifact file reads: [GHSA-7v78-v35x-cqg5](https://github.com/advisories/GHSA-7v78-v35x-cqg5) and [issue #2176](https://github.com/netease-youdao/LobsterAI/issues/2176); and
- JeecgBoot anonymous chat-attachment SSRF: [GHSA-wwv2-c3p6-cpr5](https://github.com/advisories/GHSA-wwv2-c3p6-cpr5) and [issue #9672](https://github.com/jeecgboot/JeecgBoot/issues/9672).
- TinyAGI unauthenticated message, `prompt_file`, and response-attachment boundaries: [GHSA-w22m-c8rq-w42r](https://github.com/advisories/GHSA-w22m-c8rq-w42r), [issue #284](https://github.com/TinyAGI/tinyagi/issues/284), [GHSA-2r4w-xxv7-6r74](https://github.com/advisories/GHSA-2r4w-xxv7-6r74), [issue #283](https://github.com/TinyAGI/tinyagi/issues/283), [GHSA-69rx-5vq2-c562](https://github.com/advisories/GHSA-69rx-5vq2-c562), and [issue #282](https://github.com/TinyAGI/tinyagi/issues/282);
- NanoClaw child-agent privilege inheritance: [GHSA-grxx-9qr2-2q6v](https://github.com/advisories/GHSA-grxx-9qr2-2q6v) and [issue #2807](https://github.com/nanocoai/nanoclaw/issues/2807); and
- `openclaw-cn` wrapper approval, elevated-sender, and dangling-symlink `apply_patch` boundaries: [GHSA-p2px-f69r-9h28](https://github.com/advisories/GHSA-p2px-f69r-9h28), [issue #563](https://github.com/mf-yang/openclaw-cn/issues/563), [GHSA-f57q-9mhr-fhmm](https://github.com/advisories/GHSA-f57q-9mhr-fhmm), [issue #564](https://github.com/mf-yang/openclaw-cn/issues/564), [GHSA-2mj8-f2gc-5q5j](https://github.com/advisories/GHSA-2mj8-f2gc-5q5j), and [issues #565–566](https://github.com/mf-yang/openclaw-cn/issues/565).
- OpenChamber default-auth, command-route, and workspace-read boundaries: [GHSA-xj9x-9j3p-fff9 / CVE-2026-53975](https://github.com/advisories/GHSA-xj9x-9j3p-fff9), [GHSA-9wgq-4cmq-jhvv / CVE-2026-53976](https://github.com/advisories/GHSA-9wgq-4cmq-jhvv), and the [project correction](https://github.com/openchamber/openchamber/commit/f1b9506132faf6c564a2694c7f33b94421a49b4a); and
- LudusMCP credential-dialog description-to-command boundary: [GHSA-5ccg-4qw3-g338 / CVE-2026-19045](https://github.com/advisories/GHSA-5ccg-4qw3-g338) and [project issue #2](https://github.com/NocteDefensor/LudusMCP/issues/2); and
- LudusMCP direct CLI-wrapper and guide-path boundaries: [GHSA-grhp-mc55-jxg8 / CVE-2026-19047](https://github.com/advisories/GHSA-grhp-mc55-jxg8), [project issue #3](https://github.com/NocteDefensor/LudusMCP/issues/3), [GHSA-6j8j-xrrf-px36 / CVE-2026-19046](https://github.com/advisories/GHSA-6j8j-xrrf-px36), and [project issue #4](https://github.com/NocteDefensor/LudusMCP/issues/4).
- Nanobot shell allow-list, login-shell environment, and MCP capability-scope boundaries: [GHSA-m259-67hc-p7v5 / CVE-2026-19243](https://github.com/advisories/GHSA-m259-67hc-p7v5), [issue #4521](https://github.com/HKUDS/nanobot/issues/4521), [merged fix #4562](https://github.com/HKUDS/nanobot/pull/4562), [GHSA-hfxr-wggc-4cr6 / CVE-2026-19245](https://github.com/advisories/GHSA-hfxr-wggc-4cr6), [issue #4518](https://github.com/HKUDS/nanobot/issues/4518), [GHSA-qwp6-wxvx-2jc8 / CVE-2026-19244](https://github.com/advisories/GHSA-qwp6-wxvx-2jc8), [issue #4435](https://github.com/HKUDS/nanobot/issues/4435), and [merged fix #4436](https://github.com/HKUDS/nanobot/pull/4436).
- August 8 MCP wrapper and local journey-path records: context-engine `review-git-diff` [GHSA-fjwc-rc47-268g / CVE-2026-19266](https://github.com/advisories/GHSA-fjwc-rc47-268g), mcp-bridge-api server command/argument dispatch [GHSA-c8c4-xf97-vvc8 / CVE-2026-19263](https://github.com/advisories/GHSA-c8c4-xf97-vvc8), MCPGateway Claude usage-range handling [GHSA-8cv7-xjpc-f5hw / CVE-2026-19268](https://github.com/advisories/GHSA-8cv7-xjpc-f5hw), and mcp-ui-probe journey/usage storage [GHSA-h8jj-pqww-5m4w / CVE-2026-19270](https://github.com/advisories/GHSA-h8jj-pqww-5m4w).
- August 8 local MCP tool follow-ups: mcp-pdf-vision `load_pdf` `pdfPath`/`sessionId` handling [GHSA-jgc6-5vgc-hvqg / CVE-2026-19279](https://github.com/advisories/GHSA-jgc6-5vgc-hvqg) and slidev-builder-mcp `generateChart` `outputDir` handling [GHSA-wgq9-x672-9734 / CVE-2026-19281](https://github.com/advisories/GHSA-wgq9-x672-9734).
- August 8 MCP memory/history/manifest path follow-ups: memory-graph domain storage [GHSA-4297-h6wq-2qm5 / CVE-2026-19285](https://github.com/advisories/GHSA-4297-h6wq-2qm5) and [issue #14](https://github.com/aaronsb/memory-graph/issues/14), mindpilot-mcp history storage [GHSA-6cmv-x2ph-3gc2 / CVE-2026-19287](https://github.com/advisories/GHSA-6cmv-x2ph-3gc2) and [issue #24](https://github.com/abrinsmead/mindpilot-mcp/issues/24), and rive-mcp-server-core library manifests [GHSA-4p6x-rj5h-hg93 / CVE-2026-19288](https://github.com/advisories/GHSA-4p6x-rj5h-hg93) and [issue #2](https://github.com/astralisone/rive-mcp-server-core/issues/2); and
- August 8 project/Git wrapper follow-ups: coder-api project creation [GHSA-745r-gxf5-fh45 / CVE-2026-19284](https://github.com/advisories/GHSA-745r-gxf5-fh45) and [issue #9](https://github.com/MauricioMilano/coder-api/issues/9), plus llm_memory_mcp `auto.capture` [GHSA-rrf2-j3h9-99wg / CVE-2026-19282](https://github.com/advisories/GHSA-rrf2-j3h9-99wg) and [issue #21](https://github.com/andreahaku/llm_memory_mcp/issues/21).
- August 9 `react-analyzer-mcp` project-root traversal: [GHSA-g23h-49jw-gw6q / CVE-2026-19323](https://github.com/advisories/GHSA-g23h-49jw-gw6q) and [project issue #3](https://github.com/azer/react-analyzer-mcp/issues/3).
- August 9 local session, workspace, memory, callback, and delete path follow-ups: claude-sesh session enrichment [GHSA-rm8c-j3vq-fv9j / CVE-2026-19327](https://github.com/advisories/GHSA-rm8c-j3vq-fv9j) and its [committed correction](https://github.com/abracadabra50/claude-sesh/commit/786c9d74800e6d0858b65778f31beb71b3983a50), skill-ninja-mcp-server workspace operations [GHSA-866p-rrc7-6r5x / CVE-2026-19328](https://github.com/advisories/GHSA-866p-rrc7-6r5x) and its [0.1.1 correction](https://github.com/aktsmm/skill-ninja-mcp-server/commit/855b46739e0f6e8388f17f9d0066ac4298a3965d), roo-code-memory-bank-mcp-server memory files [GHSA-46jg-c454-8hm3 / CVE-2026-19325](https://github.com/advisories/GHSA-46jg-c454-8hm3) and [issue #7](https://github.com/IncomeStreamSurfer/roo-code-memory-bank-mcp-server/issues/7), shadcn-vue-mcp callback files [GHSA-3r2r-p86c-vj94 / CVE-2026-19324](https://github.com/advisories/GHSA-3r2r-p86c-vj94) and [issue #14](https://github.com/HelloGGX/shadcn-vue-mcp/issues/14), and Ai-doctor image deletion [GHSA-rhch-h3c6-w784 / CVE-2026-19326](https://github.com/advisories/GHSA-rhch-h3c6-w784) and [issue #1](https://github.com/Jevon-Zhong/Ai-doctor/issues/1).
- August 9 approval, skill-version, canvas, and memory-library path follow-ups: spec-workflow-mcp `categoryName` [GHSA-xgwr-j735-3wg4 / CVE-2026-19336](https://github.com/advisories/GHSA-xgwr-j735-3wg4), [issue #220](https://github.com/Pimzino/spec-workflow-mcp/issues/220), and [correction](https://github.com/Pimzino/spec-workflow-mcp/commit/9c7a7839e690bb4543f0e7481b5740d23808e5fe); skill-vision-control `skillName` [GHSA-j882-vpg7-hqjh / CVE-2026-19335](https://github.com/advisories/GHSA-j882-vpg7-hqjh) and [issue #2](https://github.com/Jane-xiaoer/skill-vision-control/issues/2); obsidian-mcp-server canvas operations [GHSA-6p38-w68x-9w82 / CVE-2026-19331](https://github.com/advisories/GHSA-6p38-w68x-9w82) and [issue #3](https://github.com/bazylhorsey/obsidian-mcp-server/issues/3); and advanced-reasoning-mcp system/library storage [GHSA-rgqf-fgw4-cmhv / CVE-2026-19330](https://github.com/advisories/GHSA-rgqf-fgw4-cmhv) and [issue #3](https://github.com/angrysky56/advanced-reasoning-mcp/issues/3).
- August 9 local process-wrapper follow-ups: Supabase-MCP `generate_types` schema [GHSA-xw8f-8xpv-55vg / CVE-2026-19333](https://github.com/advisories/GHSA-xw8f-8xpv-55vg) and [issue #2](https://github.com/NightTrek/Supabase-MCP/issues/2), MCP4EDA design/waveform fields [GHSA-92x2-9gq9-2w2v / CVE-2026-19332](https://github.com/advisories/GHSA-92x2-9gq9-2w2v) and [issue #3](https://github.com/NellyW8/MCP4EDA/issues/3), Ollama-mcp model-copy fields [GHSA-pq7w-6xmw-3jgj / CVE-2026-19334](https://github.com/advisories/GHSA-pq7w-6xmw-3jgj) and [issue #5](https://github.com/NightTrek/Ollama-mcp/issues/5), and codex_mcp model selection [GHSA-5pgh-4pr5-mhm8 / CVE-2026-19329](https://github.com/advisories/GHSA-5pgh-4pr5-mhm8) and [issue #1](https://github.com/andreahaku/codex_mcp/issues/1).
- August 9 outbound-fetch and static-route follow-ups: mcp-google-search `read_webpage` URL handling [GHSA-jg2j-2qmx-58vq / CVE-2026-19337](https://github.com/advisories/GHSA-jg2j-2qmx-58vq), [issue #11](https://github.com/adenot/mcp-google-search/issues/11), and [correction](https://github.com/adenot/mcp-google-search/commit/f071d491b685011ca04e8ab8d586fc65f86bcee1); plus LoLLMs SPA catch-all decoding [GHSA-37c2-pxv8-c2mx / CVE-2026-10595](https://github.com/advisories/GHSA-37c2-pxv8-c2mx) and [correction](https://github.com/parisneo/lollms/commit/9bc6431ae7b708da76d51e7626a7cf48ff2b1d24).
- August 9 MCP output-path and outbound-fetch follow-ups: MCPyATS Mermaid `folder`/`name` handling [GHSA-q9qj-38cq-3792 / CVE-2026-19338](https://github.com/advisories/GHSA-q9qj-38cq-3792) and [issue #22](https://github.com/automateyournetwork/MCPyATS/issues/22), ProjectHub-Mcp Webhooks API `url` handling [GHSA-qp9j-gfjj-6h3v / CVE-2026-19340](https://github.com/advisories/GHSA-qp9j-gfjj-6h3v) and [issue #176](https://github.com/anubissbe/ProjectHub-Mcp/issues/176), and Alibaba Cloud DataWorks MCP resource-URI handling [GHSA-jgm8-jqmm-5rc5 / CVE-2026-19339](https://github.com/advisories/GHSA-jgm8-jqmm-5rc5) and [issue #27](https://github.com/aliyun/alibabacloud-dataworks-mcp-server/issues/27).
- August 9 MCP local-file, output-path, and attachment-fetch follow-ups: LudusMCP `insert_creds_range_config` paths [GHSA-hj87-3g9g-3832 / CVE-2026-19366](https://github.com/advisories/GHSA-hj87-3g9g-3832) and [issue #5](https://github.com/NocteDefensor/LudusMCP/issues/5), LudusMCP `read_range_config` URL sources [GHSA-6fh8-4v8j-r4gw / CVE-2026-19367](https://github.com/advisories/GHSA-6fh8-4v8j-r4gw) and [issue #6](https://github.com/NocteDefensor/LudusMCP/issues/6), gemsuite-mcp Gemini file inputs [GHSA-5r3x-hrv2-fg58 / CVE-2026-19368](https://github.com/advisories/GHSA-5r3x-hrv2-fg58) and [issue #3](https://github.com/PV-Bhat/gemsuite-mcp/issues/3), jira-mcp-server public-URL attachments [GHSA-rmrp-j9qh-xwh9 / CVE-2026-19369](https://github.com/advisories/GHSA-rmrp-j9qh-xwh9) and [issue #6](https://github.com/KS-GEN-AI/jira-mcp-server/issues/6), and image-gen-mcp upscale output paths [GHSA-xm38-q6p9-jrgg / CVE-2026-19365](https://github.com/advisories/GHSA-xm38-q6p9-jrgg) and [issue #6](https://github.com/Ichigo3766/image-gen-mcp/issues/6).
- August 10 MCP file/fetch follow-ups: article-scraper-mcp `fetch_article` URLs [GHSA-wmf6-8cmx-6fp6 / CVE-2026-19375](https://github.com/advisories/GHSA-wmf6-8cmx-6fp6) and [issue #3](https://github.com/dmitriiweb/article-scraper-mcp/issues/3), KoboldCPP-MCP-Server `apiUrl` [GHSA-m2hf-r4mh-rrq8 / CVE-2026-19373](https://github.com/advisories/GHSA-m2hf-r4mh-rrq8) and [issue #3](https://github.com/PhialsBasement/KoboldCPP-MCP-Server/issues/3), api-mcp proxy URLs [GHSA-g33v-9g6g-xm9p / CVE-2026-19374](https://github.com/advisories/GHSA-g33v-9g6g-xm9p) and [issue #4](https://github.com/adafap/api-mcp/issues/4), handwriting-ocr-mcp-server document paths [GHSA-pxv6-pv74-gcg3 / CVE-2026-19372](https://github.com/advisories/GHSA-pxv6-pv74-gcg3) and [issue #6](https://github.com/Handwriting-OCR/handwriting-ocr-mcp-server/issues/6), claude-comfyui-mcp upload paths [GHSA-g57q-682f-hr5f / CVE-2026-19371](https://github.com/advisories/GHSA-g57q-682f-hr5f) and [issue #3](https://github.com/Nikolaibibo/claude-comfyui-mcp/issues/3), and new-mcp session paths [GHSA-w5g7-c885-pm69 / CVE-2026-19370](https://github.com/advisories/GHSA-w5g7-c885-pm69) and [issue #10](https://github.com/bartekke8it56w2/new-mcp/issues/10).
- August 11 mcp-grafana caller-selected destination: [GHSA-fr94-7cqc-vjrq / CVE-2026-19516](https://github.com/advisories/GHSA-fr94-7cqc-vjrq) and the [Grafana advisory](https://grafana.com/security/security-advisories/cve-2026-19516/).

The GHSA entries are unreviewed mirrors except where a source record says otherwise. Many cited project issues remain open, and the mirrors do not independently establish remote transport exposure. The committed spec-workflow-mcp and mcp-google-search corrections identify versions 2.2.7 and a post-0.3.1 revision respectively; the LoLLMs mirror identifies version 3 as corrected. The four process-wrapper issues and the skill-vision-control, obsidian-mcp-server, advanced-reasoning-mcp, MCPyATS, ProjectHub-Mcp, DataWorks MCP, LudusMCP, gemsuite-mcp, jira-mcp-server, image-gen-mcp, article-scraper-mcp, KoboldCPP-MCP-Server, api-mcp, handwriting-ocr-mcp-server, claude-comfyui-mcp, and new-mcp records identify no corrected release in their mirrors. Treat every release range as a validation seed and confirm the deployed commit, route exposure, configuration, and current project status before reporting.

!!! warning "Denied sinks and synthetic data only"
    Use disposable agent instances, fake status objects, synthetic memory rows, temporary canary roots, owned no-content HTTP peers, and patched tool/file/network/process sinks. Never read host files, persist real conversation content, execute commands, probe internal services, or relay credentials or responses.

## 1. Inventory the final authority surface

Before testing payloads, capture one trace that joins configuration to the final action:

1. listener address, reverse-proxy path, and route authentication;
2. conversation/portal mode and caller identity;
3. requested toolsets plus explicit denies;
4. the final model-visible schemas and dispatcher allow-list;
5. approval classification and remembered session grants;
6. raw and canonical path or URL;
7. the final file, process, or connector sink; and
8. the returned or outbound delivery channel.

This prevents partial findings. A model-visible tool is not yet executable; a risky-looking command is not an approval bypass; and a private-looking URL is not SSRF until the final connector selects the owned canary peer.

## 2. Compare route authentication across operating modes

The LettaBot record describes `GET /api/v1/pairing/:channel` and `GET /api/v1/status` skipping API-key rejection when the effective portal mode is `shared`. Build a disposable server with synthetic agent, channel, pairing, and conversation identifiers. Keep the listener local or on an isolated lab network.

Create a route matrix across:

- no credential, invalid credential, and valid fake API key;
- default, `shared`, and per-channel/per-user modes;
- empty and populated synthetic pairing state; and
- direct listener versus the intended reverse-proxy path.

Record status, response schema or field-name hash, effective mode, and whether the authentication middleware ran. A bounded positive is **same unauthenticated request denied in the restrictive control mode but returns synthetic management metadata in shared mode**. Do not enumerate real pairing requests or conversation identifiers. Report mode-dependent route authorization, not a universal application takeover.

TinyAGI adds a capability-bearing message route. Patch the provider process constructor and compare unauthenticated and authenticated canary messages across provider adapters. Record route middleware, selected agent/provider, configured tool policy, approval mode, and final argv. The bounded positive is **unauthenticated `POST /api/message` -> normal queue and agent invocation -> provider recorder receives `--dangerously-skip-permissions` or an equivalent pre-approved mode**. Do not send a tool-seeking prompt or execute the provider; argv evidence is enough.

OpenChamber adds a default-configuration variant where the authentication middleware reportedly becomes a no-op when `UI_PASSWORD` is absent, while `/api/fs/exec` reaches a process launcher. In a disposable instance, replace process creation with a denied argv recorder and compare absent, empty, invalid, and valid synthetic password configurations. Send only an inert operation marker. Capture listener exposure, middleware branch, effective authentication state, route match, structured command/argument representation, and denied spawn. A bounded positive is **no configured password -> anonymous request passes the route gate -> process recorder receives caller-controlled execution intent**. Do not execute a command or preserve command output.

## 3. Recompute deny policy after every tool injection

The Hermes record states that built-in memory tools were filtered for `disabled_toolsets=['memory']`, after which provider schemas such as `fact_store` and `fact_feedback` were appended and inserted into the runtime's valid-tool set. This is a general test for plugins, MCP servers, provider tools, aliases, and dynamically discovered capabilities.

For each tool source, snapshot:

```text
requested enabled/disabled sets
-> built-in schema filter
-> provider/plugin injection
-> model-visible tool names
-> dispatcher-valid tool names
-> approval rule
-> patched handler result
```

Use a temporary memory provider whose handlers only record a random marker. Compare default policy, explicit allow, explicit deny, deny plus provider enabled, aliases, and reload/reconnect behavior. Require the explicit deny to win at both schema and dispatch time.

A strong result is **denied category absent after the first filter -> provider injects a member of that category -> patched handler receives the marker**. Stop before a real memory write. Preserve tool-name/provenance and decision traces, not prompt or conversation bodies.

The Mercury and CowAgent records add two useful variants. Mercury accepts `allowedTools` for a delegated child but supplies the full capability registry when the child actually runs, including sibling orchestration tools. CowAgent initially creates a reduced Self-Evolution review agent, then a later MCP synchronization step appends configured tools before schema generation.

Add delegated and background agents to the policy matrix. Create two inert child agents and one fake MCP tool whose handler only records a marker. Compare the declared child allow-list, construction-time tools, final model-visible schemas, dispatcher-valid names, target-object ownership, and patched handler result. A bounded positive is **restricted child/reviewer starts without a capability -> runtime registry or MCP reconciliation restores it -> denied tool recorder receives the marker**. For orchestration tools, patch halt/delete operations and record the synthetic target agent ID; do not interrupt real work.

Nanobot adds a capability-*class* variant. In affected builds, `enabledTools` filtered `list_tools()` results but resource and prompt wrappers were registered separately. Build a fake MCP server with one inert tool, resource, and prompt; set `enabledTools: []`; and capture the model-visible schemas plus the final `read_resource`, `get_prompt`, and tool dispatch decisions. The bounded positive is **deny-all blocks the ordinary tool -> resource or prompt wrapper still appears -> patched wrapper receives the marker**. Also test a specific tool list and `*`; the merged correction allows resource/prompt registration only for the wildcard policy. Do not return real resource content or submit the prompt to a live model.

NanoClaw adds a construction-time identity variant. Patch child-agent creation and configuration persistence, then compare the parent caller's identity and policy with the child owner, workspace, tool allow-list, environment, and channel bindings. A bounded positive is **ordinary parent reaches child creation -> caller-controlled fields select a stronger child mode or inherited authority -> patched creator records the elevated configuration**. Child creation alone is not privilege escalation; preserve the exact authority delta and deny every real tool action.

## 4. Differential-test approval parsing against execution parsing

The IronClaw record describes risk classification splitting shell chains on some separators while `sh -c` also recognized newline. Its merged correction adds newline/CRLF and wrapper-aware regression coverage. Reuse that methodology wherever an agent remembers approval for a command tool.

Replace process creation with an argv/script recorder. Compare semantically equivalent inert markers encoded with:

- semicolon, newline, CRLF, pipe, and conditional separators;
- quoting, escaping, line continuation, and surrounding whitespace;
- direct shell `-c`, `env ... sh -c`, timing/wrapper utilities, and option values that invoke helpers; and
- ask-each-time versus remembered/session auto-approval.

For every case, record raw text, classifier tokens, risk level, approval decision, final interpreter/argv tuple, and whether the recorder would dispatch one or multiple commands. The bounded positive is **control encoding pauses -> equivalent alternate encoding inherits approval -> final parser trace contains a second command**. Never execute either command. Keep parser disagreement, approval inheritance, and command execution as separate claims.

Nanobot's `exec.allowPatterns` follow-up applies the same principle even without remembered approval. The affected guard used `re.search()` on the complete raw command while the sink passed that string to `bash -c`; one matching prefix could therefore authorize additional shell segments. Use a denied spawn recorder and compare one allowed marker with semantically inert chains separated by `&&`, `||`, `;`, pipe, newline, comments, quotes, escapes, and nested parentheses. Record which segments the guard recognizes and the final shell parse. A positive is **one segment matches -> a non-matching second segment survives the guard -> denied sink records both operations**. The merged fix splits top-level `&&`, `||`, `;`, and pipe operators while respecting quotes, escapes, and parentheses, so newline/comment and wrapper variants remain important independent controls rather than assumed coverage.

### Compare curated environments with the shell's reconstructed environment

A reduced `env` map is not authoritative when the process starts a login shell. The Nanobot record says affected `exec` calls defaulted to `bash -l -c` or `zsh -l -c` while forwarding `HOME`, allowing startup files to reintroduce variables that the curated environment omitted.

1. Create a temporary `HOME` containing a synthetic startup file that exports only a random canary variable.
2. Patch process creation or use a no-command shell harness that records argv and the post-startup environment without exposing host variables.
3. Compare omitted `login`, `login=false`, and `login=true` across Bash, Zsh, a non-login shell, absent startup files, and a different temporary `HOME`.
4. Capture the curated environment, shell argv, startup files consulted, and whether the canary appears after shell initialization.

The bounded positive is **canary absent from the child environment supplied by the agent -> default `-l` shell reads the temporary profile -> canary appears at the recorder**. Never inspect the real home directory, shell startup files, or process environment. Report ambient-policy reconstruction, not generic secret theft.

Mercury contributes two controls that should be standard in this harness:

- **redirection semantics**: a classifier can label a command family such as `echo` as read-only while the final shell interprets output redirection as a write; and
- **alternate command surfaces**: a normal `run_command` path can invoke approval while an in-chat background-command path reaches a separate shell runner without the same check.

Use marker-only command strings and replace every spawn or shell constructor with a denied recorder. Pair each alternate route with the semantically equivalent guarded tool call. A bounded positive is **guarded route requests approval -> alternate route or redirection-bearing safe family is auto-approved -> denied recorder observes the same write- or execution-capable shell semantics**. Do not create the marker file or publish a command-bearing API body.

The `openclaw-cn` record adds shell multiplexers such as `busybox sh -c` and `toybox sh -c`. Compare two inert payloads using the same outer executable after an `allow-always` decision. Capture the approved full command, resolved outer binary, persisted allow-list pattern, inner applet and payload, second approval decision, and denied spawn. A bounded positive is **first wrapper command approved -> trust persists only as the multiplexer path -> changed inner shell payload skips a second approval -> execution branch reaches the denied recorder**. If the tested build crashes before spawn, report only the missed approval and overbroad persisted trust.

LudusMCP adds a UI-helper boundary. The mirror identifies `get_credential_from_user` input reaching `SecretDialog.showSecretDialog`, with the `Description` field affecting command construction on the local host. Treat that as a source-review seed, not proof of remote MCP execution. Patch Electron/process/shell launch points, then vary only inert description markers across quotes, separators, line breaks, option-looking text, and ordinary prose. Record MCP caller, raw description, UI serialization, generated executable/argv or shell text, and denied sink. Report only if the description changes process grammar; displaying attacker-controlled text is not command injection by itself.

The two later LudusMCP mirrors add direct tool paths: `ludus_cli_execute` reportedly passes `command`/`args` through `executeArbitraryCommand` or `executeCommand`, while `ludus_environment_guides_search` uses `guide_name` in local path handling. Both records describe local access and open project issues, so do not present them as unauthenticated remote MCP exploitation or as fixed-release facts.

For the CLI wrapper, replace every process constructor with a denied argv recorder and compare structured argument arrays, a single shell-like string, option-looking values, separators, quoting, and line breaks. Capture the MCP transport and caller, raw tool arguments, normalization, selected wrapper, final executable/argv or shell grammar, and denied spawn. A bounded positive is **nominally structured tool input -> wrapper reparses it as shell syntax or changes executable selection -> denied process sink records a second operation**. Do not execute either marker.

For guide lookup, create `guides/owned.md` plus a sibling canary under a disposable root, then patch open/stat/read calls. Exercise plain names, nested names, `..`, absolute paths, encoded separators, sibling-prefix paths, and symlinks. Record raw and decoded `guide_name`, configured guide root, canonical target, containment decision, and denied syscall. A bounded positive is **guide identifier -> canonical sibling path -> denied read sink**, not disclosure. Never point the tool at real Ludus, workspace, home, or credential files.

### Bind elevated chat authority to stable sender identity

For chat-controlled elevated modes, compare stable sender identifiers with recipient/self fields and mutable profile metadata. Use two synthetic chat users and patch session-state persistence.

Test allow-list values against sender ID, normalized sender address, recipient address, display name, username, tag, case changes, and provider prefixes. Record the general command gate separately from the narrower elevated gate. The bounded positive is **command-authorized but non-elevated sender -> recipient or mutable metadata matches the elevated allow-list -> `/elevated` state recorder receives an enable transition**. Do not execute an elevated tool; the unauthorized state transition is sufficient.

## 5. Bind file tools to a canonical allowed root and delivery authority

NanoClaw's record links an absolute path accepted by `send_file` to an outbox delivery path. The super-agent-party record links non-HTTP `file_url` input to local file handling through a manually executable tool. Test both the read authority and the subsequent response/delivery authority.

Create a temporary layout containing:

```text
allowed-root/document.txt
sibling-root/canary.txt
allowed-root/link-to-sibling -> ../sibling-root/canary.txt
```

Patch `open`, copy, and outbox/send functions so they only record the requested path and deny the syscall. Exercise relative paths, absolute paths, `..`, sibling-prefix names, symlinks, dangling final symlinks, encoded separators, `file:` forms, and path-like strings that are not HTTP(S) URLs.

Record input, decoded path, `realpath`/final target, allowed-root decision, tool provenance, and attempted response/outbox destination. A bounded positive is **untrusted tool/API input -> canonical target outside the temporary allowed root -> denied read/copy sink reached -> normal response or delivery path selected**. Never point the harness at home directories, credentials, project source, or production mounts.

Also test passive artifact parsing. The LobsterAI record describes assistant/tool text containing a `MEDIA:` or `file:` path being parsed in the renderer, automatically forwarded across an Electron preload/IPC bridge, and resolved by a main-process file reader when the session opens. Seed only a synthetic session message and patch `stat`/`readFile` at the main-process boundary. Record message provenance, parsed artifact path, session root, final canonical target, IPC method, and denied syscall. The strongest bounded claim is **message-derived path outside the disposable workspace -> automatic preview loader -> denied main-process reader**; a rendered artifact label alone is not file disclosure.

TinyAGI contributes two end-to-end file-authority variants. First, an unauthenticated agent-configuration route can persist a caller-selected `prompt_file`, which prompt construction later reads and sends to the model provider. Second, provider/agent output containing a `[send_file: path]` tag can enter an outbound channel attachment queue. Use a temporary canary file, patched `readFile`/provider body recorder, and patched Telegram/Discord/WhatsApp attachment constructors. A bounded positive is **unauthenticated route or influenced model output -> outside-workspace canary path -> denied reader or attachment sink -> provider/outbound delivery authority selected**. Never let canary contents reach a live model or messaging account.

gemsuite-mcp adds the same boundary inside nominal file-enabled Gemini tools. Trace both `file_path` and `file_paths` through request construction, the final file read, base64 conversion, and the outbound Gemini body. Use a random synthetic file and patch the reader and provider client before either can return or transmit bytes. A bounded positive is **MCP file selector -> canonical sibling canary -> denied reader -> provider-body recorder identifies the selected attachment slot**. Prove scalar and multi-file paths independently; a local read attempt does not establish that bytes reached Gemini, and provider-body construction does not establish a provider accepted them.

OpenChamber adds explicit read-route controls: `/api/fs/read`, `/api/fs/stat`, and `/api/fs/raw` reportedly accept `allowOutsideWorkspace=true` with an absolute path. Build only temporary workspace and sibling-canary roots. Compare the flag absent, false, true, malformed, and duplicated across relative, absolute, sibling-prefix, and symlink cases. Patch `stat` and read syscalls, and capture the raw parameter, selected root policy, canonical target, authentication state, and denied final path. A bounded positive is **anonymous or low-authority request -> override flag disables workspace confinement -> canonical sibling canary reaches the denied reader**. Never point the route at host secrets or use file-read evidence to forge a session.

For workspace mutation tools, include dangling final symlinks, not only existing symlinks and `..`. The `openclaw-cn` record describes a component walk returning success on `ENOENT` before the final `writeFile` follows an in-workspace dangling symlink to an outside target. Create only a disposable symlink and patch the final writer. Record lexical path, nearest existing ancestor, `lstat` result, symlink target, intended final location, and denied write. The positive is **direct traversal denied -> dangling in-root alias accepted -> final write recorder resolves outside the temporary root**; do not create the outside file.

## 6. Distinguish URL detection from final-peer enforcement

The super-agent-party proxy record describes a private-address check that logged a warning but returned the URL to the connector. A detector without a deny transition is not an enforcement control.

Use two owned no-content peers representing allowed and denied destinations. Patch or wrap the connector to record, but not issue, the request. Exercise hostnames, literal addresses, redirects, DNS changes between validation and connect, mixed/encoded IP forms, user-info, explicit ports, and scheme changes.

Capture:

```text
raw URL -> parsed authority -> DNS answers -> policy result
-> redirect/final authority -> connector destination -> response relay decision
```

A strong result is **policy classifies the target as denied or private -> execution continues -> connector recorder receives that peer**. Do not contact metadata, loopback services, private production ranges, or arbitrary Internet hosts. If the connector is not reached, report only a validation inconsistency.

### August 11 follow-up: override headers are destination capabilities

The mcp-grafana record describes `X-Grafana-URL` overriding the configured Grafana origin while `grafana_api_request` separately controls method, path, and body. An earlier correction reportedly stripped the configured service-account token from unintended destinations but did not constrain the destination itself. Treat these as independent properties: **credential non-forwarding does not make arbitrary server-side fetch safe**.

Use one owned Grafana-like control peer and one owned no-content denied peer. Patch DNS and the final connector so neither request leaves the harness. Compare absent, empty, duplicate, mixed-case, comma-joined, user-info, path-bearing, redirecting, and differently encoded override headers across every MCP transport and direct HTTP wrapper. Pair each with harmless `GET`/`HEAD` canary paths and a denied non-GET control; never target metadata, loopback services, or private production ranges.

Record configured origin, raw header values, framework duplicate-header behavior, parsed override origin, tool-selected method/path/body, resolved and final peer, attached credential names, connector event, and response-relay decision. A bounded positive is **untrusted MCP caller -> override header selects the owned denied peer -> patched connector receives the request -> synthetic response would return through the tool**, even when no Grafana token is attached. Report credential forwarding only if a fake token name independently survives into the denied request recorder.

For AI chat attachments, trace one step further. The JeecgBoot record describes an anonymous `files` URL being downloaded, parsed as an allowed document type, and inserted into model context. Use an owned no-content document server and a patched parser/model-context sink. Capture route authentication, URL policy, resolved peer, redirect chain, downloaded media/extension decision, parser invocation, and whether a random marker would enter context. A bounded positive is **anonymous attachment URL passes incomplete address policy -> connector selects the owned denied peer -> synthetic document marker reaches the patched context builder**. Never request private services or let retrieved content reach a live model.

## August 8 follow-up: trace MCP arguments to the final process or file sink

The four later mirrors add a compact review heuristic: a field that looks structured at the MCP schema is still untrusted grammar if a utility later joins it into shell text or treats an identifier as a filename. Do not infer network reachability from the package name. Record the actual transport, route registration, authentication, caller role, tool exposure, and deployment topology first.

### Git and server-command wrappers

Use disposable repositories and replace every `spawn`, `exec`, shell, Git, and wrapper constructor with a denied recorder. Exercise only inert grammar markers.

| Record | Input under test | Final authority to capture |
| --- | --- | --- |
| context-engine `review-git-diff` | `args` supplied to `execGitCommand` | executable, argv array, repository cwd, environment, and any shell reparse |
| mcp-bridge-api Servers endpoint | `command` and `args` | selected server/process, structured argv versus joined shell text, and denied spawn |
| MCPGateway usage-range endpoint | `since` passed through `getUsageByDateRange` | date parser result, generated Claude command, final argv/shell text, and denied spawn |
| mcp-pdf-vision `load_pdf` | `pdfPath` and `sessionId` | PDF utility selection, temporary/session path, executable/argv, and any shell reparse |
| slidev-builder-mcp `generateChart` | `outputDir` | chart utility arguments, canonical output root, executable/argv, and any shell reparse |
| coder-api project creation | Git `url`, `branch`, and `depth` from REST or MCP | generated clone operation, argument boundaries, destination root, and denied spawn |
| llm_memory_mcp `auto.capture` | caller-selected Git `hash` | every generated `git show` invocation, repository cwd, and denied spawn |
| Supabase-MCP `generate_types` | `schema` | generated Supabase CLI invocation, executable/argv, cwd, and shell reparse |
| MCP4EDA `run_openlane` / `view_waveform` | `design_name` / `vcd_file` | selected EDA utility, executable/argv, workspace, and shell reparse |
| Ollama-mcp model operations | `name`, `modelfile`, `source`, `destination` | every Ollama/copy helper invocation and argument boundary |
| codex_mcp `ask` | `model` | Codex executable/argv, option boundary, cwd, environment, and shell reparse |

For each surface compare a normal scalar, structured list, option-looking value, whitespace, quotes, separators, line breaks, and duplicate/array/object representations. Include direct helper calls and the actual HTTP/MCP route because framework coercion may change the type before the wrapper sees it. Capture raw JSON, schema validation, coerced value, generated command representation, executable, argv, shell flag, cwd, environment, and recorder event.

The bounded positive is **caller-controlled field accepted as data -> wrapper changes command grammar or executable/argument boundaries -> denied process recorder observes an additional inert operation or attacker-selected executable**. A string containing metacharacters is not sufficient. Never execute Git hooks, shell commands, package helpers, or a real Claude CLI, and do not preserve repository content in evidence.

The local MCP mirrors identify affected functions but do not independently establish remote transport exposure. For mcp-pdf-vision, join both `pdfPath` and `sessionId` to the final utility and temporary-path construction. For slidev-builder-mcp, join `outputDir` to both path canonicalization and the chart-generation process call. For coder-api, compare its REST and MCP project-creation entry points against the same patched Git sink. For llm_memory_mcp, trace the revision through every `git show` helper rather than stopping at the first call. Pair direct function tests with the actual registered schema, because validation or coercion may differ. A useful result requires the denied process trace to show changed grammar; an outside-root output path without shell re-interpretation is a separate file-confinement finding.

### Journey IDs and filenames are file capabilities

For mcp-ui-probe, create a temporary journey root with `owned.json` and a sibling canary. Patch read, delete, analysis-load, and usage-stat filesystem calls. Exercise `journeyId` and `filename` through `get_journey`, `delete_journey`, `analyze_journey`, and `usage_stats` using plain IDs, nested paths, `..`, encoded separators, absolute paths, sibling-prefix paths, existing symlinks, dangling symlinks, and nonexistent controls.

Record raw and decoded input, extension/default-name handling, configured root, lexical path, canonical target, operation, and denied syscall. Require the same final-path confinement for reads, analysis, statistics, and deletes. The bounded positive is **local or authenticated journey selector -> canonical sibling canary -> denied read/delete/stat recorder**. Do not open or remove the canary, and do not describe this as remote traversal unless the tested deployment independently exposes the route to a remote caller.

### Trace one identifier across every file lifecycle operation

The memory-graph, mindpilot-mcp, and rive-mcp-server-core records expand the journey-ID heuristic beyond one read or delete helper. An identifier may be accepted during creation, retained in an object, and reused later for reads, saves, overwrites, imports, or cleanup. Review the full lifecycle, not just the route named by an advisory.

Build a disposable layout with an intended storage root and sibling canaries whose extensions match each product's generated suffix. Patch the final `open`, `readFile`, `writeFile`, `unlink`, and rename/replace calls. Then exercise:

- memory-graph domain creation, selection, memory retrieval, and save using the same domain ID;
- mindpilot-mcp history update, collection update, and delete using the same route ID; and
- rive-mcp-server-core import and manifest save using the same `libraryId`.

Compare plain IDs, nested names, `..`, absolute paths, encoded separators at the transport layer, sibling-prefix paths, Windows drive/UNC forms where supported, existing and dangling symlinks, and generated suffix edge cases. Record raw input, decoded value, appended extension, lexical and canonical target, operation, route/tool authentication, and denied syscall.

A bounded positive is **caller-controlled identifier -> generated filename canonicalizes outside the temporary root -> one or more denied lifecycle sinks receive the sibling canary path**. Report the exact proven operations separately; a write-path result does not imply read or delete authority. Never open, overwrite, or remove the canary, and do not infer remote exploitability from an MCP package or HTTP route without independently proving listener and authentication state.

### Treat project names as recursive-scan capabilities

The `react-analyzer-mcp` issue describes the `analyze-project` tool passing caller-controlled `projectName` into `path.join(PROJECT_ROOT, subFolder)`, recursively enumerating the result, and reading discovered `.jsx` and `.tsx` files. The durable boundary is **identifier -> scan root -> recursive enumeration -> extension filter -> file read -> tool result**, not just a string containing `..`.

Create a disposable project root with one synthetic React file, a sibling directory with a second marker-only React file, and non-React controls in both directories. Patch directory enumeration and `readFileSync` so they record canonical paths and deny access before returning content. Exercise the actual MCP schema and direct helper with:

- a normal project identifier and nested in-root project;
- `..`, absolute paths, encoded separators at the transport layer, sibling-prefix names, and repeated separators;
- existing directory symlinks, a symlinked React file, and broken-link controls; and
- case and separator variants appropriate to the deployed operating system.

Capture the raw JSON value, schema/coercion result, `PROJECT_ROOT`, joined path, canonical scan root, every visited directory, every candidate extension decision, and denied file sink. A bounded positive is **caller-selected project name -> canonical scan root outside the temporary project root -> sibling `.jsx`/`.tsx` canary reaches the denied reader**. Do not return source content, traverse home or repository directories, or call this remote arbitrary-file read unless the tested MCP transport and authentication independently establish remote caller access.

Repeat on any corrected revision and require confinement before recursive traversal begins. A basename-only rejection is insufficient if absolute paths or symlinks still select a sibling root. Also verify that the same canonical root is retained through documentation generation and response serialization; do not assume the first join is the only path decision.

### Map path authority by operation, not by parameter name

The five later records show why a generic traversal check is incomplete: similar path-like inputs reach materially different authority. `sessionId` selects claude-sesh enrichment data; `workspacePath` scopes skill installation, update, `AGENTS.md` editing, and uninstall; `file_name` reaches memory read and append operations; `filepath` reaches a callback-file reader; and `imagePath` reaches deletion. Build one disposable root per product plus a marker-only sibling, then replace every final file operation with a denied recorder.

| Surface | Input | Lifecycle sinks to trace |
| --- | --- | --- |
| claude-sesh `getEnrichedData` / `enrichSession` | `sessionId` | session directory selection, metadata/stat, enrichment reads, and response serialization |
| skill-ninja-mcp-server installer | `workspacePath` | skill inventory, install destination, update/replace, `AGENTS.md` write, uninstall, and cleanup |
| roo-code-memory-bank-mcp-server | `file_name` | memory-bank root join, read, append/create, and returned tool result |
| shadcn-vue-mcp callback server | `filepath` | callback parsing/coercion, canonical target, file read, MIME/response handling |
| Ai-doctor file management | `imagePath` | stored image identifier lookup, canonical target, unlink/remove, and record cleanup |
| spec-workflow-mcp approval creation | `categoryName` | approval directory/filename generation, create/write, later lookup, and cleanup |
| skill-vision-control version lookup | `skillName` | versions-directory selection, enumeration, metadata reads, and returned inventory |
| obsidian-mcp-server canvas tools | canvas path/name | read, create/write, replace, and returned canvas result |
| advanced-reasoning-mcp systems/libraries | system/library selector | create, get/read, switch, overwrite, and persisted active-library state |
| MCPyATS `generate_mermaid_markdown` | `folder` and `name` | generated Markdown filename, parent creation, write/replace, and returned path |
| LudusMCP `insert_creds_range_config` | `configPath` and `outputPath` | YAML read, credential transform, parent creation, write/replace, and returned paths |
| gemsuite-mcp Gemini tools | `file_path` and `file_paths` | local read, base64 request-part construction, and outbound provider body |
| image-gen-mcp `upscale_images` | `output_path` plus each input basename | output-directory creation, generated filename, image write/replace, and returned path |
| handwriting-ocr-mcp-server `upload_document` | `File` | canonical source selection, denied read, OCR request construction, and returned result |
| claude-comfyui-mcp `comfy_upload_image` | `image_path` | canonical source selection, denied copy, ComfyUI upload destination, and returned metadata |
| new-mcp `geminithinking` | `sessionCommand` and `sessionPath` | existence check, read, create/write, replace, and returned session result |

Exercise direct helper calls and the registered HTTP/MCP entry point with a normal in-root value, nested names, `..`, absolute paths, encoded separators, sibling-prefix paths, duplicate/object/array coercions, existing symlinks, dangling symlinks, and nonexistent controls. For generated filenames, capture suffix addition before and after canonicalization. For a caller-supplied workspace root, verify it is selected from trusted server configuration rather than merely checking that the requested target is below the caller's chosen root.

Capture the raw transport value, decoded/coerced value, configured authority root, lexical target, canonical target, operation, identity/role, and denied syscall. The bounded positive is **caller-controlled selector -> canonical sibling canary -> operation-specific denied sink**. Report read, append/create, replace, and delete separately; reaching one does not prove the others. For skill-ninja, a particularly useful matrix compares inventory, install, update, `AGENTS.md` mutation, uninstall, and cleanup with the same `workspacePath`, because a root accepted by a read-only listing helper may later authorize destructive lifecycle operations.

Do not open, write, replace, or delete the canary. These mirrors describe local access and do not establish remote transport exposure, so join any source-level result to the actual listener, authentication, and tool-registration path before claiming remote reachability. On corrected claude-sesh and skill-ninja revisions, require confinement at every sink rather than treating the first rejected helper as complete coverage.

### Compare framework normalization with the final path parser

The LoLLMs record adds an unauthenticated SPA catch-all variant: the web framework can normalize one representation while a later `pathlib` join resolves encoded dot segments into a different file. Build a disposable static root and sibling canary, replace file response/open calls with denied recorders, and compare raw `..`, `%2e%2e`, mixed-case encodings, encoded separators, double decoding, repeated slashes, absolute paths, sibling prefixes, and symlink controls. Capture the raw request target, proxy/framework path, router parameter, every decode pass, joined path, canonical target, and denied file sink.

The bounded positive is **anonymous catch-all request -> framework accepts a normalized route -> later path parser selects the sibling canary -> denied file responder records the outside-root target**. Do not retrieve host files or infer secret disclosure. On the corrected revision, require rejection or confinement after the final decode and canonicalization step, not merely a new raw-string filter.

### Apply final-peer enforcement to MCP URL and URI capabilities

For mcp-google-search, ProjectHub-Mcp webhooks, DataWorks MCP resources, LudusMCP `read_range_config`, jira-mcp-server `add_attachment_from_public_url`, article-scraper-mcp `fetch_article`, KoboldCPP-MCP-Server `apiUrl`, and api-mcp's proxy route, treat every caller-controlled URL or URI as a connector capability even when the MCP server itself is local. The mirrors place authority in webhook, resource, range-config, attachment, article, model-backend, and generic proxy selectors; do not assume labels such as “article,” “API,” “resource,” or “public URL” are enforcement controls. Use owned no-content peers and a denied connector recorder. Compare literal addresses, mixed/encoded address forms, DNS answers, redirects, DNS changes between policy and connect, alternate ports, user-info, scheme transitions, response size, and media-type handling. Preserve the exact MCP/HTTP schema, framework coercion, resource-scheme dispatch, and parser result before URL policy runs.

Trace webhook creation through initial verification, retained configuration, later delivery, retry, and redirect handling. Trace resource and range-config reads from URI parsing through scheme/handler selection, DNS, redirects, fetch, and response serialization. For Jira attachments, replace both Axios and the Jira upload client: capture the final peer and whether fetched bytes would enter an attachment body without creating an issue attachment. The positive is **caller URL/URI passes initial validation or selects the permissive handler -> redirect or resolution selects the owned denied destination class -> connector recorder receives the final authority**. Record whether bytes would be returned to the caller, stored, forwarded to a provider, or sent only as a webhook/attachment; destination control, response disclosure, and downstream relay are separate claims. Never contact metadata, loopback applications, private production ranges, arbitrary third parties, or a live Jira instance. Repeat mcp-google-search against its committed correction and require policy to run on every redirect and the actual connected peer; treat the open-issue records as source-review seeds until behavior is reproduced.

## August 19 follow-up: LLM-controlled options are destination capabilities

Six records from the August 19 GHSA wave place LLM- or caller-controlled options directly into transport or process sinks. The reusable question is the same as for URL capabilities: which field of the tool schema actually selects the final authority, and what is re-validated after the model fills it in.

- SearXNG MCP `web_url_read`: [GHSA-q87f-qc2r-2gw4 / CVE-2026-54688](https://github.com/advisories/GHSA-q87f-qc2r-2gw4) (internal-address guard disabled by default, `MCP_HTTP_HARDEN` off, literal-hostname check only), [GHSA-wppf-h75h-6pm6 / CVE-2026-54689](https://github.com/advisories/GHSA-wppf-h75h-6pm6) (hardened-mode bypasses: redirect re-follow, `0.0.0.0`, IPv4-mapped IPv6), and [GHSA-hjwh-xvfw-qrwj](https://github.com/advisories/GHSA-hjwh-xvfw-qrwj) (Basic-auth credentials in `SEARXNG_URL` exposed through STDIO `notifications/message` and JSON-RPC config errors, `< 1.12.0`);
- FAF-MCP family: [GHSA-rr55-jp92-8wp2](https://github.com/advisories/GHSA-rr55-jp92-8wp2) `claude-faf-mcp <= 5.7.1`, [GHSA-j4r7-8ph4-43g3](https://github.com/advisories/GHSA-j4r7-8ph4-43g3) `faf-mcp <= 2.1.2`, [GHSA-cc2g-gq8c-r332](https://github.com/advisories/GHSA-cc2g-gq8c-r332) `grok-faf-mcp <= 1.5.2` — unconfined `path` argument resolved (`~` expansion, `path.resolve()`) straight into local read/write with denylist-only checks;
- Contentful MCP: [GHSA-2xhg-73j7-rrgx / CVE-2026-53957](https://github.com/advisories/GHSA-2xhg-73j7-rrgx) — `export_space`/`import_space` (`exportSpace.ts` L126–141, `importSpace.ts` L103–119) spread LLM-controlled `host`/`proxy` into `contentful-export`/`contentful-import` options, overriding the CMA SDK `baseURL` so the server PAT is sent to the attacker endpoint; prompt injection via Contentful content is the input path;
- atomic-agents-stack: [GHSA-xhcr-cqfr-m3hv](https://github.com/advisories/GHSA-xhcr-cqfr-m3hv) — the HTTP MCP catalog backend (`mcp_registry/http.py`, through `<= 1.0.0`) accepts cleartext `http://` catalogs and spawns catalog-supplied `command`/`args` as stdio subprocesses; `mcp_allow_fn` defaults to `None`, so a MITM on the catalog channel yields code execution without LLM involvement.

### Harness

Run one disposable MCP server per record with a patched file/network/process sink and owned no-content peers:

- **SearXNG `web_url_read`**: default configuration (`MCP_HTTP_HARDEN` unset) versus hardened; literal private/loopback/metadata hosts, `0.0.0.0`, IPv4-mapped IPv6 literals, encoded forms, redirects from an owned peer to an owned denied peer, and DNS changes between check and connect. Also capture the STDIO `notifications/message` payload and any JSON-RPC config-error body: the bounded positive for the credential-exposure record is **credential-bearing `SEARXNG_URL` -> client-visible notification/error**, with credentials redacted in the report. Never let the reader reach a real SearXNG backend or internal range.
- **FAF-MCP `path`**: trace `getProjectPath()` and `faf_read`/`faf_write` with in-root values, `../` chains, absolute paths to a sibling canary under a disposable home root, and `~` expansion. Prove read and write at denied sinks separately; the bounded positive is **LLM-issuable tool call -> resolved path outside the `.faf` project root -> denied file sink records the sibling canary**. Prompt-injection reachability is only claimable when the tool server processes attacker-controlled content in the same session.
- **Contentful export/import**: run the tools against a lab Contentful-like origin with a synthetic space, pass a fake `host`/`proxy` pointing at an owned no-content peer, and record the CMA SDK `baseURL` plus the attached fake `Authorization` name. The bounded positive is **LLM-supplied `host` -> CMA client selects the owned denied peer -> fake PAT name observed in the denied request**. Do not use a live Contentful account or capture real tokens.
- **atomic-agents catalog**: stand up an `http://` catalog on a controlled local link that serves a catalog entry whose `command` points at a denied spawn recorder, with `https` and allowlist-positive controls. The bounded positive is **cleartext catalog entry -> `MCPClientPool` spawns the canary command at the denied process sink**. Never execute catalog-supplied commands on a shared host.

For each record, keep the raw tool argument, the validation/policy decision, the final resolved authority (peer, path, or argv), and the denied-sink event. Report capability, destination control, and credential relay as separate claims.

## October 12 21:3xZ follow-up: agent-harness approvals and sandbox returns are enforced at the wrong layer — stale read-only annotations, prefix-rule chaining, tarballs the sandbox controls, and `nsenter` without `--root`

Four legs from the 21:31Z wave extend this page's "early decision is not authoritative" invariant to the *approval* and *containment* halves of local coding-agent harnesses:

- **goose 1.28.0–<1.44.0: `readOnlyHint` annotations persist across approval-mode switches** ([GHSA-8h69-7j5q-pwfc / CVE-2026-109561](https://github.com/advisories/GHSA-8h69-7j5q-pwfc), 4.2): after a session has used Smart Approval mode, persisted read-only tool annotations are **never cleared by `update_goose_mode`**, so in Manual Approval mode a prompt-injected call to any tool annotated `readOnlyHint: true` executes **without prompting** — `PermissionInspector::inspect` trusts a stale capability bit from a mode the user already left. The user's selected approval mode is a UI state; the enforcement input is the annotation cache.
- **Continue CLI ≤1.5.47: allowed Bash **prefix** rules compose into execution via shell operators** ([GHSA-f54m-g39v-qf2p / CVE-2026-109560](https://github.com/advisories/GHSA-f54m-g39v-qf2p), 7.5): prefix-allowlist approval (`git status*`) checks only the leading tokens; instructions injected into **repository files or fetched pages** get the agent to append `; <payload>`, `&& <payload>`, or `| <payload>` after the allowed prefix — unapproved commands execute under the approved rule's cover. Prompt-injection vector is repo content itself, which every coding agent reads before asking anything.
- **Vercel deepsec 0.1.0–<1.1.17: sandbox results come home in a tarball the sandbox authored** ([GHSA-cchp-25pr-r776 / CVE-2026-109375](https://github.com/advisories/GHSA-cchp-25pr-r776), 6.1): `extractTarballLocally` follows links planted by sandboxed code (prompt-injected agents qualify), so symlink/hardlink members in the *result tarball* write arbitrary files on the orchestrator host. The return channel of a sandbox is an untrusted-input boundary with the same symlink battery this page and the July 28 zip-lib page already carry — extraction-side, not exec-side.
- **sandboxed.sh ≤1.3.0: host-namespace escape because `nsenter` omits `--root`** ([GHSA-xqq7-hjvp-gg2f / CVE-2026-109569](https://github.com/advisories/GHSA-xqq7-hjvp-gg2f), 8.8): agent-run code in the container workspace reaches the host filesystem because the tool attaches via `nsenter` **without `--root`**, so absolute paths resolve on the *host* mount namespace — documented container isolation defeated by one missing flag on the entrypoint wrapper.

Operator axes:

1. **Approval-mode audits must enumerate what survives a mode switch.** Decision table in a lab: run one tool call in the permissive mode, switch to Manual/strict, then re-trigger the same call via injected content. Anything that skips the prompt post-switch is a persisted-capability leak (annotation caches, session-level approvals, "always allow" lists, remember-me style grants — same lifecycle-revocation family as the OTRS JWT-after-demote leg). Grep fingerprint: mode/config setter that mutates a mode field but doesn't touch sibling caches.
2. **Prefix/allowlist command gates are token-boundary theater unless the full command is parsed.** Test battery per agent: an allowed-prefix command with `;`/`&&`/`|`/backtick/`$()` continuation, newline continuation, and quoting variants; the finding is any approval whose check string differs from the executed string — the same validation-vs-execution-parser differential as this page's IronClaw leg, now reached through *model steering* instead of user typing. Note the injection surface: READMEs, code comments, and fetched web pages are prompts.
3. **Enumerate every channel from sandbox → host and treat each as archive/parser input**: result tarballs, workspace syncs, log ships, artifact uploads. Run the standard link-following fixture battery (symlink out, hardlink→symlink, absolute-target) against the *host-side extractor*, plus the `nsenter`/`--root`/`--mount` flag audit on any wrapper that enters namespaces: attach flags that preserve the host mount namespace are an escape by construction, greppable in the launcher script.
4. Proof boundary: owned agent installs, disposable repos with inert marker continuations (`touch /tmp/agent-marker` class), temp-dir sandbox roots; never use real user repos or shared orchestrators.

## October 13 follow-up: workflow-platform MCP/API-tool config fields dial arbitrary peers — Conductor `mcpServer` and `specUrl`, MeterSphere Swagger3 import (CVE-2026-109402 / [GHSA-36mx-2w99-hqwq](https://github.com/advisories/GHSA-36mx-2w99-hqwq); CVE-2026-109190 / [GHSA-q2hq-xqfr-hx4g](https://github.com/advisories/GHSA-q2hq-xqfr-hx4g); CVE-2026-109189 / [GHSA-hhch-5r3f-p76p](https://github.com/advisories/GHSA-hhch-5r3f-p76p), 12:32Z wave, public exploits on the first two)

Three same-shape SSRF legs on orchestration/QA platforms where a **configuration field is the fetch destination**:

- **Conductor `MCPService.listTools(mcpServer)`** (3.22.0, `ai/.../mcp/MCPService.java`): the MCP-server URL passed to the tools-listing call is contacted server-side with no egress bound — remote-exploitable, exploit public.
- **Conductor `ListApiToolsTask.start(specUrl)`** (3.31.2, API Tool Configuration): the OpenAPI spec URL a workflow task fetches to enumerate API tools — same unbounded-fetch shape one config object away.
- **MeterSphere `Swagger3ParserApiDefinition.testUrlTimeout(swaggerUrl)`** (≤3.6.9-lts): Swagger3 import "test URL" endpoint fetches the supplied `swaggerUrl` server-side; exploit public.

Operator rules (extends this page's "tool argument → final authority" invariant to workflow platforms):

1. **Workflow/AI platforms are SSRF farms by design — the question is bound, not reach.** Every "list tools from server", "load spec from URL", "test this endpoint" feature exists *to* fetch user-supplied URLs; the test is whether the fetch honors an egress allowlist, blocks link-local/metadata ranges, and re-checks after redirects. Probe class: point the field at an owned callback, then at redirect-wrapped and rebinding variants, from the lowest-privilege role that can legitimately create a workflow/API definition (usually nearly everyone).
2. **Same-product sibling parity**: Conductor shipped two independent unbounded-fetch sinks (`listTools` and `specUrl`) in the MCP and API-tool subsystems — when one config-URL field on a platform dials arbitrary peers, enumerate every feature that ingests a URL (spec import, MCP registration, webhook test, plugin source) and treat them as separate legs with separate fix bands.
3. **Conductor/MeterSphere banner recon**: both are common on internal OT/devops networks with no auth in default installs; "can I create a workflow/API definition anonymously?" is the first question, and the config-URL fetch is the second (file:// variants and internal-range canaries on lab instances only, owned callbacks for positive proof).

## Evidence and reporting boundaries

- Include positive and negative mode/auth controls for management routes.
- Diff requested policy against both model-visible and dispatcher-valid tool sets.
- Diff construction-time and final runtime tool surfaces for child, review, plugin, provider, and MCP injection paths.
- Apply allow/deny policy to every MCP capability class, including tools, resources, and prompts.
- Prove shell parser or alternate-route disagreement with a denied spawn recorder, not command side effects.
- Preserve the MCP/HTTP schema type, framework coercion, generated argv or shell text, and final denied process sink for wrapper arguments.
- Trace stored identifiers across create, read, update, save, import, and delete operations; report only the lifecycle sinks actually reached.
- Record shell startup mode and post-startup environment separately from the environment supplied at process creation.
- Prove filesystem escape with a temporary synthetic path and denied sink, not file contents.
- For recursive scanners, preserve the selected root, visited-directory trace, extension filter, and denied reader; do not infer broad file disclosure from a path-join differential alone.
- Build an operation matrix for path selectors and prove read, write/append, replace, and delete authority independently at denied final sinks.
- Preserve every URL decode/canonicalization transition between proxy, router, framework, path library, and final file responder.
- Bind passive artifact parsing to the final IPC/file syscall before claiming a local-file-read path.
- Prove SSRF at final peer selection using an owned fixture; a warning log alone is insufficient.
- State whether evidence comes from a vendor/project record, merged fix, open issue, researcher disclosure, or unreviewed mirror.
- Do not claim universal unauthenticated access, host compromise, secret theft, or fixed-version coverage beyond the exact tested configuration and source evidence.
