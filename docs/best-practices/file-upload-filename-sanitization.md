# File uploads: don’t trust client filenames

When you accept file uploads, the **filename is attacker-controlled metadata**.

If you build filesystem paths using that value (for example `UPLOAD_DIR / file.name`), you are one `../` away from **path traversal** and **arbitrary file write**.

## The failure mode

Common vulnerable pattern:

```python
save_path = UPLOAD_DIR / e.file.name
await e.file.save(save_path)
```

Attacker-controlled names like:

- `../app.py`
- `..\\..\\Windows\\System32\\drivers\\etc\\hosts`
- `%2e%2e%2f%2e%2e%2fapp.py`

…can escape your intended directory.

## Best practice

### 1) Generate server-side filenames

- Use UUIDs / content hashes for stored names.
- Store the original filename separately (DB field / metadata) for user display.

### 2) If you must use the filename, sanitize hard

Minimum baseline:

- strip directories:
  - `Path(name).name`
- allowlist characters:
  - `[A-Za-z0-9._-]` (example)
- enforce a base directory after `resolve()`:
  - reject if the resolved path is not within `UPLOAD_DIR`.

### 3) Don’t overwrite executable/config files

Even with traversal blocked:

- store uploads in a dedicated, non-executable directory
- do not serve them from the same origin without careful content-type controls

## Detection

- Log and alert on upload filenames containing:
  - `../`, `..\\`
  - URL-encoded traversal sequences
  - absolute paths (`/`, `C:\\`)

## References

- NiceGUI example advisory (footgun): <https://github.com/advisories/GHSA-9ffm-fxg3-xrhh>
