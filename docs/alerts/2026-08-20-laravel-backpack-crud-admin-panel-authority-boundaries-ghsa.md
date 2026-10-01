---
title: Laravel Backpack CRUD admin-panel authority boundaries
---

# Laravel Backpack CRUD admin-panel authority boundaries

Eight Laravel Backpack CRUD records published 2026-08-19/20 expose one durable operator pattern: a low-code Laravel admin panel that treats the `Host` header, the request body, and the client-supplied file extension as trusted input and that applies row-scope or upload-scope policy inconsistently between read, write, and reorder paths. The strongest record is a pre-auth OS command injection path that runs on every HTTP request in production when `exec()` and `curl` are available.

Source records:

- pre-auth OS command injection in `Stats::makeCurlRequest` via attacker-controlled `Host` header: [GHSA-mrc5-3mm3-45c5 / CVE-2026-54182](https://github.com/advisories/GHSA-mrc5-3mm3-45c5);
- CRUD panel query scopes not enforced on Update, Delete, and Reorder (cross-tenant IDOR): [GHSA-vgmv-8xjc-6rch / CVE-2026-54180](https://github.com/advisories/GHSA-vgmv-8xjc-6rch);
- arbitrary file deletion via attacker-controlled `clear_<attr>[]`: [GHSA-8xjm-wqrp-2f25 / CVE-2026-54178](https://github.com/advisories/GHSA-8xjm-wqrp-2f25);
- unverified password change via mass assignment in `MyAccountController`: [GHSA-xpv2-hrfc-hw62 / CVE-2026-54175](https://github.com/advisories/GHSA-xpv2-hrfc-hw62);
- `HasUploadFields` preserves the attacker-supplied file extension: [GHSA-8q2w-pv9p-mjvc / CVE-2026-54177](https://github.com/advisories/GHSA-8q2w-pv9p-mjvc);
- `SingleBase64Image` accepts any base64 payload behind a `data:image` prefix: [GHSA-8hw4-7qjr-3wxg / CVE-2026-54179](https://github.com/advisories/GHSA-8hw4-7qjr-3wxg);
- login-email change without a current-password check: [GHSA-9fw9-8c49-qch8 / CVE-2026-54176](https://github.com/advisories/GHSA-9fw9-8c49-qch8);
- cross-tenant record re-parenting in HasMany/MorphMany relation fields: [GHSA-42vx-43vc-x6pr / CVE-2026-57570](https://github.com/advisories/GHSA-42vx-43vc-x6pr).

Confirm the exact Backpack CRUD version, the `CRUDServiceProvider` / `CRUDServiceProvider::boot()` state, whether `exec()` is available to the web process, and the `public` disk configuration before testing. The `Host`-header RCE path requires `exec()` and `curl` to be available and a web server that does not strip malformed `Host` headers; default hardened nginx/Apache configurations reject many of the required payloads.

!!! warning "Lab-only, synthetic tenants, and marker-only sinks"
    Use a disposable Backpack CRUD install on a synthetic tenant, two lab users (one low-priv, one admin), a denied `exec()` recorder, a denied storage-deleter recorder, and a denied file-writer recorder. Never target production admin panels, real tenant data, shared `public` disks, or real user credential columns. Do not upload shell payloads or execute arbitrary OS commands on production systems.

## Boundary map

| Surface | Intended authority | Untrusted input | Bounded positive |
| --- | --- | --- | --- |
| `Stats::makeCurlRequest` | no user-controlled shell input | `Host` header value on any production request | `exec()` invoked with a crafted shell argument; denied recorder captures the command line |
| CRUD Update/Delete/Reorder | row-scope enforced via `addBaseClause` / `addClause` | record primary key on write operations | out-of-scope record primary key accepted on write path while read path rejects it |
| `clear_<attr>[]` | delete only files belonging to the current record | disk-relative paths in the `clear_<attr>[]` array | denied deleter records a delete outside the record's file set |
| `MyAccountController::postAccountInfoForm` | restricted to `AccountInfoRequest::validationData()` keys | arbitrary `fillable` columns via mass assignment | `password` or `email` field mutated through the account-info endpoint |
| `HasUploadFields` | extension allowlist at the uploader layer | client-supplied file extension | a `.php`-suffixed canary reaches the `public` disk |
| `SingleBase64Image::uploadFiles` | MIME-validated base64 image | any base64 payload behind `data:image` | a non-image payload lands on disk with no recognizable extension |

The finding is the broken binding, not the HTTP 200 or the UI rendering. Capture the input representation, the authorization or scope decision, the canonical database object or file path, and the harmless sink separately.

## 1. Pre-auth `Host`-header command injection

`Backpack\CRUD\Stats::makeCurlRequest` builds a shell command using unescaped input from the HTTP `Host` header and passes it to `exec()`. The vulnerable path is reached from `BackpackServiceProvider::boot()` on every production HTTP request when `exec()` and `curl` are available. A 1-in-100 random gate is the only guard; an attacker retries until the gate is open.

Replayable validation:

1. Stand up a disposable Backpack CRUD install on a lab web server that does **not** strip malformed `Host` headers. Confirm `exec()` is enabled for the web process and `curl` is on `PATH`.
2. Patch `exec()` with a recorder that captures the full command line and rejects before execution. Do not run the command.
3. Send a request with a crafted `Host` header that breaks out of the intended shell argument. The exact shape depends on the version; capture the raw command line the recorder observes.
4. Send a control request with a well-formed `Host` header. The recorder should observe the expected `curl` invocation.
5. Repeat on the fixed build where the `Host` value is escaped or the gate is removed.

A bounded positive is **malformed `Host` header -> `Stats::makeCurlRequest` -> `exec()` invoked with a shell argument containing the attacker's marker**, on the affected build only. Report the exact `Host` shape, the web server's `Host` handling, the `exec()` availability, and the recorder's command-line capture. Do not claim RCE from the `exec()` call alone; RCE additionally requires a reachable execution sink, which is a separate untested precondition.

## 2. Cross-tenant IDOR on write paths

Backpack CRUD's list and read operations apply any query scopes registered via `addClause()` / `addBaseClause()` (tenant isolation, user ownership). The Update, Delete, and Reorder operations fetch records directly from the unscoped model query, so an authenticated user who knows a record's primary key can modify or delete records outside their scope.

Replayable validation:

1. Use a lab Backpack CRUD install with two synthetic tenants and two lab users (one per tenant).
2. Configure a CRUD panel that uses `addBaseClause` to restrict rows to the caller's tenant.
3. Confirm the control: user A's list view shows only A's records.
4. Send user A an Update, Delete, or Reorder request for a record belonging to user B.
5. Record: the request path, the primary key used, the scope decision on the write path, and the final record state.

A bounded positive is **user A's write request for user B's primary key -> unscoped model query -> record state mutated or deleted**, while the same primary key is rejected on the read path. Do not target real tenant data or destructive operations; use marker records only.

## 3. Arbitrary file deletion via `clear_<attr>[]`

`HasUploadFields::uploadMultipleFilesToDisk` reads file paths from the `clear_<attribute>[]` request input and deletes them from the configured storage disk without verifying that the paths belong to the current model record. The safe pattern already exists in the codebase (`MultipleFiles.php` intersects the requested deletions against the stored file list); the trait method lacks that intersection.

Replayable validation:

1. Use a lab Backpack CRUD install with the `upload_multiple` field pattern and a `public` disk.
2. Create a synthetic model record with two marker files on the `public` disk.
3. Create a second synthetic file outside the record's file set.
4. As a user with Update access on the CRUD, submit a `clear_<attr>[]` array containing the out-of-scope file's path.
5. Patch `Storage::disk()->delete()` with a denied recorder that captures the requested path and rejects before deletion.

A bounded positive is **attacker-supplied `clear_<attr>[]` path -> trait method -> denied deleter records a path outside the record's file set**. Do not delete real files; the proof is the denied-sink record.

## 4. Unverified password and email change

Two `MyAccountController` records expose the same root cause: `postAccountInfoForm` uses `$request->except(['_token'])` or `$request->validated()` to update the user model, bypassing the restricted-key validation that `ChangePasswordRequest` enforces. The default Laravel 11 `User` model has `$fillable = ['name','email','password']`, so any of those fields can be mutated through the account-info endpoint without a current-password check.

Replayable validation:

1. Use a lab Backpack CRUD install with the default `User` model.
2. Create a synthetic admin account.
3. Send a `POST /admin/edit-account-info` request that includes a new `password` or `email` value and the session CSRF token.
4. Record: the request body, the mass-assignment decision, and the final user-model state.
5. Contrast with `POST /admin/change-password`, which requires `old_password` and uses `Hash::check`.

A bounded positive is **attacker's `edit-account-info` request -> user model's `password` or `email` field mutated -> account takeover path established**, while the `change-password` endpoint requires the current password. Do not target real accounts or real credential columns; use synthetic accounts only.

## 5. Extension-preserving uploads and SVG-with-script

Two upload records share the same shape: the uploader preserves the client-supplied file extension (or accepts any base64 payload behind a `data:image` prefix) without an allowlist or MIME check. On installations using a `public` disk with `php artisan storage:link`, this allows an authenticated administrator to upload a file with a server-executable extension that the web server will pass to the PHP interpreter.

Replayable validation:

1. Use a lab Backpack CRUD install with a `public` disk and `storage:link` enabled.
2. Create a synthetic CRUD panel that uses the `uploadFileToDisk` or `withFiles()` pattern.
3. As an authenticated lab admin, submit a canary file with a `.php` extension (for the extension-preservation record) or a base64 payload that decodes to a non-image type (for the `SingleBase64Image` record).
4. Patch the file-writer sink with a denied recorder that captures the written path and extension.
5. Confirm the file landed on the `public` disk with the attacker's extension or no extension.

A bounded positive is **attacker-supplied extension / base64 payload -> uploader -> file written to the `public` disk with the attacker's extension**, on the affected build only. Do not upload shell payloads or test execution on production systems; the proof is the file-on-disk evidence.

## 6. Cross-tenant record re-parenting

HasMany/MorphMany relation fields allow cross-tenant record re-parenting when the CRUD form exposes a relationship field. An authenticated, low-privileged admin user can submit a primary key for a related record outside their tenancy boundary, and Backpack will associate that record with the current parent model.

Replayable validation:

1. Use a lab Backpack CRUD install with two synthetic tenants and a CRUD panel that exposes a HasMany relation field.
2. Create a synthetic related record belonging to tenant B.
3. As a tenant A admin, submit an Update request for a tenant A parent record that includes tenant B's related record primary key in the relation field.
4. Record: the request body, the relation-processing decision, and the final related-record state.

A bounded positive is **tenant A's Update request -> HasMany/MorphMany relation processing -> tenant B's record associated with tenant A's parent**, while the read path rejects tenant B's record. Do not target real tenant data; use marker records only.

## Reporting heuristics

Lead with the crossed boundary, not the version:

- **`Host` header -> shell argument -> `exec()` invocation, pre-auth on every production request**
- **row-scope read path -> unscoped write path, cross-tenant IDOR**
- **record-bound file list -> attacker-supplied disk path, arbitrary file deletion**
- **restricted-key validation -> mass-assignment bypass, unverified password/email change**
- **extension allowlist -> client-supplied extension, `public`-disk file write**
- **record-scope relation picker -> unscoped relation primary key, cross-tenant re-parenting**

Strong reports include the exact Backpack CRUD version, the `public` disk configuration, `exec()` availability, the route and request shape, the scope or scope-decision trace, the denied-sink evidence, and the fixed-build negative control. For the `Host`-header RCE, state clearly whether the web server strips malformed `Host` headers and whether `exec()` is available to the web process; those two preconditions determine whether the path is reachable in a given deployment.

## October 1 follow-up: Laravel `APP_DEBUG=true` in production — the single-request .env disclosure (folded)

**Cadmos LTI application** ([GHSA-2h69-w2xf-8972](https://github.com/advisories/GHSA-2h69-w2xf-8972), 9.3, fixed on or before 2026-09-02): a publicly hosted Laravel app ran with `APP_DEBUG=true, APP_ENV=local`; one unauthenticated GET that triggers an unhandled exception returns the **entire server environment — every `.env` variable in plaintext** — in the debug page.

This is the exemplar for a first-touch check that costs one request per host: on every PHP/Laravel-fingerprinted target (error-page style, `laravel_*` cookie names, `/forge` paths, stack-trace formatting), append a request that predictably 500s (unauthenticated route that requires a parameter, malformed Accept header, oversized input) and inspect the error surface for Ignition/Whoops debug panels. The `APP_DEBUG` page leaks DB credentials, app keys, mail/API tokens — app-key exposure is not theoretical: it enables signed-cookie forgery against the same app. Decision table: production-looking error (generic 500) = clean; framework debug page = **immediate critical**, capture only the *names* of leaked variables in evidence, never their values, and report without re-triggering on shared tenants. Adjacent same-batch mobile items tracked without publication: Joyland AI Android pack (cleartext HTTP opt-in, trust-all TLS validators, on-path JS injection into Weex WebView bridge → clipboard/arbitrary HTTP via the `stream` module) — each leg is an already-promoted mobile class (certificate-validation-absence, cleartext policy, WebView bridge authority; see the Aug 5 Electron/protocol-authority page for the bridge-privilege invariant).
