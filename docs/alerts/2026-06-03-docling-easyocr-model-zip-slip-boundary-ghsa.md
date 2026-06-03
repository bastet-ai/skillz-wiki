# Docling EasyOCR model ZIP extraction boundary

**Sources:** [GHSA-cjqg-rq2h-2fvj](https://github.com/advisories/GHSA-cjqg-rq2h-2fvj), [Docling advisory](https://github.com/docling-project/docling/security/advisories/GHSA-cjqg-rq2h-2fvj), [Docling 2.91.0 release](https://github.com/docling-project/docling/releases/tag/v2.91.0)  
**Affected package:** PyPI `docling` `< 2.91.0`, patched in `2.91.0`.  
**Operator value:** source-assisted validation of model-download and archive-extraction boundaries in AI/OCR document-processing pipelines.

## Why this matters

GHSA-cjqg-rq2h-2fvj documents unsafe ZIP extraction in Docling's EasyOCR model download path. Before `2.91.0`, ZIP members were extracted without validating that each member stayed under the intended model directory. If an attacker controls, compromises, or can intercept the model archive source, traversal members such as `../` paths can write outside the model cache to locations writable by the Docling process.

The durable testing lesson is: **model bootstrap code is supply-chain attack surface when it downloads and extracts archives at runtime.** Treat OCR, ML, and document-conversion model downloads like plugin installers: verify archive member canonicalization, destination confinement, integrity checks, and write permissions before relying on the pipeline boundary.

## Recon targets

Prioritize explicitly authorized environments where Docling or similar document-processing services download OCR/model assets dynamically:

- ingestion workers that call Docling on user-uploaded PDFs, images, Office files, or scanned forms;
- container images that bootstrap EasyOCR or other models on first run instead of baking them into the image;
- internal data-processing jobs with broad write access to application, cache, home, startup, or SSH directories;
- air-gapped or proxy-routed deployments that mirror model assets from internal object storage;
- CI, notebook, or agent pipelines that install `docling` and run document extraction against untrusted samples.

Source-review starting points:

```bash
# Dependency reachability.
grep -R 'docling\|easyocr' -n requirements*.txt pyproject.toml poetry.lock uv.lock Pipfile.lock setup.cfg setup.py 2>/dev/null
python - <<'PY'
import importlib.metadata as m
for pkg in ['docling', 'easyocr']:
    try:
        print(pkg, m.version(pkg))
    except m.PackageNotFoundError:
        pass
PY

# Runtime model/bootstrap paths.
grep -R 'download_model\|EasyOCR\|easyocr\|model.*zip\|zipfile\|extractall' -n . 2>/dev/null
```

A dependency-only match is not enough for a strong finding. Look for a reachable code path where the running service downloads and extracts model archives, especially when the download source is configurable or mirrored.

## Safe validation workflow

Use a local lab, a disposable container, or an explicitly authorized internal environment. Do not attempt to poison public model hosts, tamper with shared mirrors, or intercept traffic outside the approved test scope.

### 1. Confirm version and reachability

```bash
python - <<'PY'
import importlib.metadata as m
for pkg in ['docling', 'easyocr']:
    try:
        print(f'{pkg}=={m.version(pkg)}')
    except m.PackageNotFoundError:
        print(f'{pkg}: not installed')
PY
```

Then identify whether the application actually triggers Docling's EasyOCR model-download functionality at runtime. Prefer source review, container entrypoint review, and lab traces over production probing.

### 2. Map the archive-to-filesystem boundary

Document the boundary before testing:

| Boundary | Question to answer |
| --- | --- |
| Download source | Is the model archive fetched from a public URL, internal mirror, object bucket, proxy, or configurable endpoint? |
| Transport/integrity | Are TLS validation, checksums, signatures, or pinned digests enforced before extraction? |
| Extraction root | Which cache/model directory receives the archive contents? |
| Canonicalization | Are ZIP member paths resolved with `realpath` or equivalent before writes? |
| Privilege | Which user owns the process, and what paths can it write? |
| Trigger | Can an attacker influence when model download/bootstrap happens? |

### 3. Use an inert ZIP Slip canary in a lab

Create only harmless marker files in a disposable directory. Keep canaries outside secrets, startup paths, shell configuration, or executable search paths.

```bash
python - <<'PY'
from pathlib import Path
from zipfile import ZipFile

lab = Path('/tmp/docling-zip-slip-lab')
lab.mkdir(parents=True, exist_ok=True)
archive = lab / 'model-canary.zip'
with ZipFile(archive, 'w') as z:
    z.writestr('safe/model.bin', 'safe marker\n')
    z.writestr('../zip-slip-canary.txt', 'inert traversal marker\n')
print(archive)
PY
```

Validation evidence should show the behavioral difference between affected and patched extraction logic:

- affected logic writes or attempts to write a traversal member outside the extraction root in the lab;
- patched logic rejects the traversal member or confines extraction under the intended directory;
- the running application path uses `docling` `< 2.91.0` and can reach the model-download extraction branch.

Do not replace real model archives or point production services at a malicious archive unless the program owner explicitly approves that supply-chain simulation.

### 4. Controls to avoid false positives

| Control | Expected result |
| --- | --- |
| `docling` `2.91.0` or later | Traversal members are rejected or remain confined to the extraction root |
| Safe ZIP with normal relative members | Model extraction succeeds inside the intended directory |
| Traversal ZIP against a generic scanner only | Do not report unless Docling's reachable model-download path is affected |
| Non-writable parent directories | Impact is limited to paths writable by the process user |
| Integrity-pinned internal model mirror | Poisoning the archive source requires a separate mirror/integrity bypass |

If the application has a separate user-controlled archive upload/extraction path, report that as its own archive traversal issue rather than overfitting it to GHSA-cjqg-rq2h-2fvj.

## Reporting heuristic

Frame the finding around a model-bootstrap archive boundary:

- **Expected boundary:** model ZIP members must be canonicalized and constrained under the model cache before any write.
- **Observed bypass:** a Docling `< 2.91.0` EasyOCR model-download path extracts traversal members outside the target directory in a lab or authorized mirror simulation.
- **Impact:** arbitrary file write as the Docling process user if the model archive source is attacker-controlled, compromised, or intercepted.
- **Evidence:** package version, reachable model-download trigger, archive source path, redacted configuration, inert canary result, and patched-version control.

## Scope and safety notes

- Keep testing to lab or explicitly approved mirror-simulation environments.
- Do not tamper with public model sources or shared production mirrors.
- Avoid writing to startup scripts, SSH keys, package files, or executable paths unless explicit command-execution validation is authorized.
- Do not collect documents, OCR outputs, credentials, or model artifacts unrelated to the boundary proof.
