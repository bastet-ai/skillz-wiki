# APScheduler serializer RCE and BillaBear identifier-injection boundaries

## Operator value

GitHub Advisory Database updates on June 4, 2026 surfaced two reusable validation patterns for authorized application assessments:

- APScheduler JSON/CBOR job serializers can instantiate attacker-selected Python classes and inject object state during deserialization: [GHSA-9cfw-f3f9-7mm7 / CVE-2026-31072](https://github.com/advisories/GHSA-9cfw-f3f9-7mm7).
- BillaBear metric filtering and aggregation paths interpolate user-controlled filter names / aggregation properties as SQL identifiers while parameterizing only values: [GHSA-xp6r-8pcc-xv5p / CVE-2026-31069](https://github.com/advisories/GHSA-xp6r-8pcc-xv5p).

The durable lesson is not the product names alone: test places where structured data is treated as trusted code metadata. Scheduler payloads may cross into Python object construction, and reporting/metrics APIs may protect values while leaving identifier positions injectable.

## Affected surfaces

| Surface | Affected versions noted by GHSA | Required position | Boundary to test |
| --- | --- | --- | --- |
| APScheduler JSONSerializer / CBORSerializer | `apscheduler >= 4.0.0a1, <= 4.0.0a6` in GHSA version data; advisory text also calls out 3.10.x and 4.0.0a5 context | ability to write or tamper with serialized scheduler job data consumed by an app | untrusted JSON/CBOR job store data to Python class import / `__setstate__` execution |
| BillaBear EventRepository | `billabear/billabear <= 2025.01.03` | authenticated `ROLE_ACCOUNT_MANAGER` or equivalent access to metric/event reporting filters | API-controlled filter keys or aggregation properties to SQL identifier fragments |

## Recon workflow

1. Confirm scope permits scheduler/job-store testing and billing or metrics API testing. These checks can mutate state; use lab tenants, disposable accounts, and explicit test data.
2. Inventory candidate dependencies and deployment paths:

   ```bash
   grep -R "apscheduler\|billabear/billabear" \
     requirements*.txt pyproject.toml poetry.lock Pipfile.lock composer.lock 2>/dev/null
   ```

3. For APScheduler, determine whether jobs are serialized through JSON/CBOR and where the serialized records live: database job store, message queue, cache, file, import/export feature, or admin API.
4. For BillaBear-style metrics endpoints, map every request field that names a metric, filter, group, aggregation, sort key, or property. Prioritize fields that are object keys rather than normal parameter values.
5. Establish a benign baseline before any canary. A strong finding compares normal behavior with one minimal malformed identifier or deserialization marker under the same role and dataset.

## Safe validation patterns

### APScheduler JSON/CBOR deserialization boundary

Use a local replica or an explicitly authorized staging job store. The goal is to prove attacker-controlled serialized job data reaches dynamic class import/state restoration; do not run destructive commands.

1. Capture the normal serialized shape for one harmless scheduled job.
2. Insert only a canary object reference that is safe in the target environment. Prefer a class you control in a lab harness whose `__setstate__` writes a fixed marker under `/tmp`, then remove it after testing.
3. Trigger the same scheduler load path the application uses: restart worker, reload job store, or call the approved import endpoint.
4. Record whether the payload is rejected, treated as inert data, or imported and restored as a Python object.

A lab-only harness can use this marker pattern to prove reachability without touching production data:

```python
# lab_canary.py in an isolated test environment only
class SkillzSchedulerCanary:
    def __setstate__(self, state):
        with open('/tmp/skillz_apscheduler_deser_canary', 'w', encoding='utf-8') as f:
            f.write('apscheduler_deser_canary')
```

Evidence should show the serializer in use, the job-store record under test, the load path, and whether `/tmp/skillz_apscheduler_deser_canary` appeared in the lab. Do not include exploit chains that execute shells or access secrets.

### BillaBear metric identifier injection

This is an identifier-context SQL injection pattern: values may be parameterized while keys are concatenated into SQL. Use a disposable tenant and a tiny metric dataset.

1. Baseline with a normal metric filter and aggregation request.
2. Mutate only the field/key that names a metric, filter, group, or aggregation property.
3. Use low-impact probes that distinguish parser behavior without changing data:

```json
{
  "filters": {
    "createdAt) /* skillz_identifier_canary */": "2026-06-04"
  },
  "aggregation": "count"
}
```

Alternative probes for endpoints that expose sort/group/field controls:

```text
metricName desc, (select 1) --
metricName) /* skillz_identifier_canary */
```

Report only if the response shows SQL syntax errors, altered query semantics, measurable time behavior from a database-only sleep primitive approved by scope, or another clear signal that the identifier crossed into SQL. Stop before data extraction; prove boundary failure with canaries and minimal response differences.

## Evidence to capture

- Exact package name, version/range evidence, and feature path that makes the vulnerable code reachable.
- Role or data-write capability needed to place the payload: scheduler admin, job-store writer, import user, or account manager.
- Minimal benign and canary request/record pairs with tenant IDs, tokens, database names, and customer data redacted.
- For APScheduler: serializer type, job-store backend, load trigger, and canary side effect from a lab or approved staging system.
- For BillaBear: the identifier field tested, baseline response, canary response, and proof that values remained parameterized while identifiers did not.

## Report framing

Frame both as trust-boundary bugs in metadata handling:

- APScheduler: serialized scheduler metadata is not just data; it can direct Python imports and object state restoration.
- BillaBear: API field names and aggregation properties are SQL syntax, not values, so value parameterization alone is insufficient.

Keep validation bounded to inert canaries and authorized replicas or test tenants.

## Sources

- GitHub Advisory Database: [GHSA-9cfw-f3f9-7mm7 / CVE-2026-31072](https://github.com/advisories/GHSA-9cfw-f3f9-7mm7)
- APScheduler proof reference linked from GHSA: [nedlir gist 11fb77f35a59cbba73392a086b02a9c6](https://gist.github.com/nedlir/11fb77f35a59cbba73392a086b02a9c6)
- GitHub Advisory Database: [GHSA-xp6r-8pcc-xv5p / CVE-2026-31069](https://github.com/advisories/GHSA-xp6r-8pcc-xv5p)
- BillaBear proof references linked from GHSA: [nedlir gist 2377ba6e7fa2ad957210b52aa8e400d9](https://gist.github.com/nedlir/2377ba6e7fa2ad957210b52aa8e400d9), [nedlir gist a50725b94650467f0593b8f4009ae19e](https://gist.github.com/nedlir/a50725b94650467f0593b8f4009ae19e)
