# Apple container pf rule-injection boundary checks

Source: hourly offensive-security scan, 2026-07-16 GitHub advisory update. Primary entry: [GHSA-39g5-644c-qwcg](https://github.com/advisories/GHSA-39g5-644c-qwcg).

This advisory is durable because it captures a reusable operator pattern: a CLI subcommand that is safe only when its generated configuration grammar stays constrained accepts user-controlled text, writes that text into a privileged parser file, and then loads it as root. For Apple `container`, the `container system dns create --localhost` flow can place a newline-bearing domain name into a macOS `pf` anchor comment, breaking out of the comment and loading an extra packet-filter rule. The useful test is the sudo/automation delegation boundary, not a destructive firewall payload.

!!! warning "Authorized validation only"
    Keep proofs to disposable macOS lab hosts or VMs where Apple `container` is explicitly in scope, synthetic DNS names, lab-only `pf` anchors, and inert marker rules such as loopback-only redirects or comments that can be removed immediately. Do not redirect production traffic, block endpoints, alter customer firewall policy, capture network data, or rely on social-engineering delivery.

## What changed

| Advisory | Component | Boundary | Operator value |
| --- | --- | --- | --- |
| [GHSA-39g5-644c-qwcg](https://github.com/advisories/GHSA-39g5-644c-qwcg) | Apple `container system dns create --localhost` | The domain-name argument is written into `/etc/pf.anchors/com.apple.container` inside a generated `pf` rule comment; newline characters can terminate the comment and inject an additional `pf` directive before `pfctl -f` loads the anchor | Test privileged CLI helpers for grammar injection when constrained sudoers entries, CI jobs, or developer automation pass user-controlled labels/domains into root-owned configuration generators. |

## Replayable validation boundaries

1. Use a disposable macOS lab host with Apple `container` `<= 0.12.2` and `pf` state that can be restored. Snapshot or back up the lab `pf` anchor before testing.
2. Confirm the intended behavior first: run `container system dns create --localhost 127.0.0.1 safe.local` and inspect only the generated lab rule class. It should create a redirect to `127.0.0.1` with the domain preserved as a comment.
3. Model the likely exposure path:
   - restricted sudoers entry that allows only `container system dns create *`;
   - CI/developer script that passes a domain from an environment variable, repository metadata, container label, or external API response;
   - admin-run helper that assumes `--localhost` means the resulting `pf` rule cannot redirect elsewhere.
4. Supply a domain string containing a newline followed by an inert, lab-safe `pf` marker directive. Prefer a rule that is syntactically visible but does not affect production traffic, or perform the proof in a disconnected VM. Avoid publishing traffic-redirection payloads.
5. Run the minimal command path needed for `pfctl -f` to load the anchor, then record whether the second directive appears as an independent rule in the loaded anchor/ruleset.
6. Add controls for patched `0.12.3`, a benign domain without newline, `--localhost` omitted, invalid IP values, shell quoting differences, and cleanup after deletion. The advisory notes that injected standalone lines may not be removed by normal domain deletion, so restore from the lab backup if needed.

Report this as **delegated root CLI helper -> user-controlled domain string crosses into `pf` grammar -> newline comment breakout loads an unconstrained packet-filter directive**. Evidence should include affected version, delegation/automation precondition, generated-anchor diff with marker-only content, loaded-rule observation, patched negative control, and cleanup/restore notes.

## Operator checklist

- [ ] Is `container system dns create` reachable through restricted `sudo`, MDM scripts, CI, task runners, or developer tooling?
- [ ] Can a non-root actor influence the domain-name argument through labels, repo files, environment variables, API responses, or docs/examples?
- [ ] Does the helper write user-controlled text into a privileged grammar (`pf`, resolver files, launchd plists, shell snippets, config includes) after validation but before loading?
- [ ] Are newline, comment, delimiter, escape, and Unicode separator characters rejected before the privileged file is written?
- [ ] Does normal cleanup remove only legitimate generated lines, leaving injected standalone grammar behind?
- [ ] Is there a patched-version or grammar-roundtrip negative control proving the injected line no longer loads?

## Reporting notes

- Lead with scope and preconditions: Apple `container` version, who can invoke the DNS subcommand, whether `sudo` is constrained, and how the domain argument is attacker-influenced.
- Keep evidence to marker-only rule diffs and lab `pfctl` observations. Redact hostnames, local network ranges, MDM policy names, sudoers contents beyond the command pattern, and automation secrets.
- Do not provide reusable redirection or blocking payloads for real networks. The finding is the privilege-boundary expansion from localhost-only redirect generation to arbitrary `pf` grammar loading.
- The same scan included an `adawolfa/isdoc` decompression-bomb advisory; it was marked processed without promotion because this run did not identify durable offensive operator value beyond bounded availability testing.
