# Andromeda Bytecode C2 Lab Workflow

## Summary

Use this skill to evaluate or operate the Andromeda research framework in an isolated, authorized lab. Andromeda combines a controller, a target listener, and a bytecode generator for delivering position-independent payload blobs to a connected host-side runtime.

Primary source: <https://github.com/vyrus001/andromeda>

## Use when

- you need to understand the trust boundaries in an agent-assisted implant / C2 proof of concept
- you are testing host-side bytecode delivery in a lab you own or are explicitly authorized to use
- you want to review how controller, listener, and generated payload artifacts interact
- you need a safe checklist before running third-party offensive tooling with committed binaries

## Components

| Tool | Directory | Runs where | Role |
| --- | --- | --- | --- |
| Soldir | `soldir/` | Controller container | FastAPI web app, graph UI, WebSocket broker, job API, Tinkr orchestration, LLM chat surface |
| Tailor listener | `tailor/tools/tailor-listen.py` | Target / host workstation | Checks in to Soldir, opens `/ws/tailor/{instance_id}`, receives `execute_bytecode`, writes blobs to a temp directory, invokes `tailor-run` |
| Tailor runner | `tailor/bin/tailor-run`, `tailor/src/` | Target / host workstation | Native C runtime that maps a blob, builds a resolver context, marks memory executable, and calls the payload entrypoint |
| Tinkr | `tinkr/` | Controller build environment | LLVM + SheLLVM-style tooling and skill fixtures that compile raw position-independent bytecode blobs |
| Artifacts | `artifacts/`, `tinkr/*.bin` | Repository / lab host | Example C sources and prebuilt bytecode blobs for deterministic smoke tests |

## Trust model

Treat every boundary as code-execution sensitive:

1. **Soldir controls Tailor**: a Tailor instance connected to Soldir accepts bytecode jobs from that Soldir server. In practice, the controller has code-execution authority over the connected host.
2. **Tailor executes untrusted blobs**: delivered bytecode is written to disk and executed through the native runner. Do not connect Tailor to a controller you do not fully trust.
3. **The WebSocket/API plane is sensitive**: unauthenticated check-in, job, graph, and Tailor WebSocket routes are acceptable only on an isolated localhost/lab network.
4. **LLM provider keys are high-value**: Soldir can receive `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `XAI_API_KEY`, and `OLLAMA_*` environment variables. Avoid using real production keys in a malware-analysis or exploit-development lab.
5. **Committed binaries need provenance checks**: rebuild host-side binaries from source where practical before execution, or inspect hashes and behavior in a disposable VM.

## Lab prerequisites

- A disposable VM or dedicated lab host. Do not use a daily-driver workstation.
- Docker for the Soldir controller container.
- The target platform expected by the payload. The included smoke workflow is documented for macOS arm64 with `/usr/bin/say`.
- Network isolation that keeps `127.0.0.1:8765` or any Docker-published `8765/tcp` endpoint away from untrusted clients.
- Written authorization for every host where Tailor runs.

## Safe startup pattern

Prefer a two-terminal lab flow so the controller and target listener are easy to stop and observe.

```bash
# Terminal 1: controller only
./stop.sh
docker compose down -v
./start.sh --no-listener

# Confirm controller state
curl -fsS http://127.0.0.1:8765/health
```

```bash
# Terminal 2: target listener on the authorized host
make -C tailor
python3 tailor/tools/tailor-listen.py \
  --soldir-url http://127.0.0.1:8765 \
  --instance-id local-lab-host \
  --verbose
```

Confirm that the health endpoint shows one checked-in Tailor client before sending any job:

```bash
curl -fsS http://127.0.0.1:8765/health
```

## Smoke-test job

Use the bundled deterministic smoke path only in a lab where an audible macOS `say` execution is acceptable.

```bash
curl -fsS -X POST http://127.0.0.1:8765/api/jobs/macos-say-smoke \
  -H 'content-type: application/json' \
  -d '{
    "target_triple": "arm64-apple-macos",
    "target_instance_id": "local-lab-host",
    "message": "authorized lab smoke test"
  }'
```

Capture job status without collecting sensitive host data:

```bash
curl -fsS http://127.0.0.1:8765/api/jobs
```

Useful fields to record: job ID, target instance ID, target triple, status, return code, stdout/stderr shape, and the exact git commit tested.

## Review checklist before running

- [ ] The repo URL, commit SHA, and current diff are recorded.
- [ ] No unexpected untracked binaries or payload blobs are present.
- [ ] `docker-compose.yml` port publishing is bound only to intended lab interfaces.
- [ ] No production LLM/API keys are exported into the container.
- [ ] Tailor listener `--soldir-url` points only at a trusted controller.
- [ ] The target instance ID is explicit; jobs are not relying on implicit target selection.
- [ ] The work directory is disposable and does not overlap sensitive paths.
- [ ] The lab has packet/process/file telemetry sufficient to explain what ran.

## Operator best practices

### Isolate the controller

- Bind Soldir to localhost or a private lab interface only.
- Add firewall rules before starting Docker if the host may publish `8765/tcp` on more than loopback.
- Do not expose `/api/jobs/*`, `/api/checkins`, `/ws`, or `/ws/tailor/*` to shared networks without adding authentication and transport security first.

### Minimize target authority

- Run Tailor as a low-privilege test user.
- Use a disposable VM snapshot and revert after each payload class.
- Keep the Tailor work directory under a temporary lab path.
- Do not run Tailor on hosts with real credentials, browser sessions, SSH agents, source code, or customer data.

### Control payload scope

- Start with deterministic fixture payloads before prompt-generated payloads.
- Keep payloads inert and visibly bounded: write a marker, print a message, or call a harmless lab binary.
- Do not test persistence, credential access, lateral movement, destructive filesystem operations, or production network callbacks from this workflow.
- Record source, compiler command, target triple, blob hash, and runtime output for each payload.

### Protect secrets

- Use throwaway LLM/API keys if provider-backed generation is required.
- Prefer local Ollama or a mock provider when reviewing orchestration behavior rather than payload quality.
- Do not place secrets in `.env` unless the file is outside version control and scoped to the disposable lab.
- Scrub logs before sharing; Tailor output and Soldir job records can reveal hostnames, instance IDs, paths, and provider configuration.

### Rebuild or verify binaries

- Prefer rebuilding `tailor/bin/tailor-run` and related libraries from source on the lab host.
- Hash committed binaries and generated blobs before execution.
- If behavior matters, compare source-built and committed artifacts in a disposable VM.
- Treat any binary or blob pulled from the repo as untrusted until verified.

## Detection and evidence hints

For authorized lab validation, useful evidence includes:

- controller HTTP and WebSocket access logs
- Tailor listener stderr/stdout
- job records from `/api/jobs`
- process creation showing `tailor-run` and the payload effect
- file writes under the Tailor work directory
- SHA-256 hashes of generated `.bin` blobs
- network captures showing only expected localhost/lab traffic

Avoid collecting unrelated host files, credentials, tokens, browser data, or user content.

## Stop and clean up

```bash
# Stop foreground Tailor with Ctrl-C, then stop Soldir
./stop.sh

docker compose down -v
```

Revert the VM snapshot after running unknown payloads or committed binaries.

## Source notes

Confirmed from the public repository on 2026-06-27:

- repo description identifies Andromeda as an implant / command-and-control framework
- README documents Tinkr, Tailor, and Soldir roles
- demo path sends an `execute_bytecode` job to a checked-in Tailor instance
- `docker-compose.yml` publishes `8765:8765` and passes LLM provider variables into Soldir
- `tailor/tools/tailor-listen.py` receives base64 bytecode and invokes `tailor/bin/tailor-run`
- `tailor/src/tailor_run.c` maps delivered blobs and marks memory executable before execution
