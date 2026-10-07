---
title: OpenSSH client-side X11 abstract-socket binding boundary
---

# OpenSSH client-side X11 abstract-socket binding boundary

[GHSA-wcvf-3x75-j4c6 / CVE-2026-55655](https://github.com/advisories/GHSA-wcvf-3x75-j4c6) describes a reusable local multi-user boundary: on a Linux SSH client host, an unprivileged local process can pre-bind the preferred abstract UNIX socket name used for forwarded X11 connections. When X11 forwarding is enabled and the client uses a local UNIX-domain X socket, the pre-bound listener may receive forwarded X11 traffic intended for the user's real display.

The GitHub record was unreviewed when this page was written. Confirm the exact OpenSSH build, Linux abstract-socket behavior, X11 forwarding mode, and vendor fix before reporting. This is not an SSH server authentication bypass and does not apply merely because TCP port 22 is reachable.

!!! warning "Disposable multi-user lab only"
    Use two synthetic local users, a fake SSH server, an empty X display, and a recorder that understands only inert canary frames. Never intercept a real desktop, keystrokes, clipboard, application window, SSH session, or forwarded X11 traffic.

## Preconditions to prove separately

| Edge | Required condition | Safe evidence |
| --- | --- | --- |
| Local contention | attacker process shares the Linux client host | second disposable UID can bind candidate abstract name |
| X11 forwarding | SSH client enables trusted or untrusted X11 forwarding | verbose client log and fake server request |
| Local transport | target display uses a UNIX-domain X socket | synthetic `DISPLAY` and socket trace |
| Name prediction | client chooses a name the local process can reserve first | bind-attempt decision table |
| Forwarding | SSH accepts the server-side X11 channel and connects locally | one inert protocol marker reaches recorder |
| Impact sink | forwarded client would trust/use X11 data | disabled/no-op X client counter only |

Do not collapse socket-name predictability, successful pre-binding, channel acceptance, and sensitive UI capture into one claim.

## Recorder-only validation workflow

1. Build a disposable Linux VM with local users `xuser-a` and `xuser-b`. Run an isolated test X server or minimal X11 protocol stub under A with no real applications, clipboard, keyboard, or display attached.
2. Run an SSH test server you control in a second VM or network namespace. Use throwaway host keys and accounts. Disable agent, credential, TCP, and filesystem forwarding so only the X11 path is under test.
3. As A, capture a clean `ssh -vvv -X` or `ssh -vvv -Y` session. Record OpenSSH build, `DISPLAY`, filesystem and abstract socket operations, allocated display number, and channel-open sequence. Redact keys and cookies.
4. Stop the session. As B, pre-bind only the candidate abstract socket name learned from the clean fixture. The listener must accept one connection, record byte counts and a fixed canary prefix, and immediately close; it must not parse or proxy arbitrary X11 messages.
5. Start the same SSH session as A. From the fake server, request one X11 channel carrying a synthetic handshake marker that contains no keyboard, clipboard, window, or application data.
6. Preserve whether OpenSSH detects the occupied name, selects another unpredictable name, falls back to a filesystem socket with safe ownership, aborts forwarding, or connects to B's recorder.
7. Repeat with the bind race lost and won, another local UID, an existing filesystem socket, abstract sockets disabled, X11 forwarding disabled, `-X` versus `-Y`, IPv4/TCP display syntax, malformed display numbers, and the fixed build.
8. Destroy both users, host keys, Xauthority fixtures, and VM snapshots after testing.

A bounded positive result is **local user B reserves the predicted abstract X socket -> user A enables X11 forwarding -> fake server opens a synthetic X11 channel -> B's recorder receives only the inert marker**. This proves local forwarded-channel interception. It does not prove capture of a real window, input, clipboard, credentials, or an SSH shell.

## Name and identity evidence

Preserve:

- raw abstract name as an escaped byte string and a hash;
- binding UID, network/user namespace, process ID, and socket state;
- target user's `DISPLAY` representation and normalized display number;
- SSH command flags and relevant effective configuration from `ssh -G`;
- fake server channel-open metadata;
- recorder connection timestamp, peer credentials where available, and canary hash;
- affected and fixed build behavior.

Linux abstract UNIX sockets are not filesystem paths. Traditional owner, mode, symlink, and directory-permission checks may not apply. Conversely, a filesystem X socket result does not automatically reproduce the abstract-socket condition. Report the namespace and socket family explicitly.

## Reporting boundaries

Include the local-host foothold and X11-forwarding preconditions in the title and impact statement. Distinguish:

1. candidate name prediction;
2. successful pre-binding by another UID;
3. OpenSSH connecting to the pre-bound listener;
4. an inert forwarded marker reaching that listener; and
5. any higher-level X11 confidentiality or manipulation impact, which should remain untested outside a vendor-provided fixture.

Do not report remote SSH compromise, server-side privilege escalation, cross-host interception, arbitrary keystroke theft, or desktop control from socket binding alone.

## October 7 follow-up: OpenSSH 10.6 batch — the ineffective-hardening-knob family (CVE-2026-106586 / CVE-2026-106582 / CVE-2026-106553 / CVE-2026-106552)

The OpenSSH 10.6 release fixed a cluster whose common denominator is **documented restriction options that did not actually restrict**:

- `restrict` in `authorized_keys` never applied to **tunnel forwarding** (`permit-tunnel` survived the "disable everything" keyword) — CVE-2026-106586.
- The **LZ77 compressed transport coder** remained negotiable even where compression was meant to be disabled — CVE-2026-106582 (the Compression-Oracle-era compression option is still a live protocol leg).
- **Credentials could persist after a failed keyboard-interactive** re-auth — CVE-2026-106553 (auth-state cleanup on failure path).
- A malicious **sftp server** can trigger directory traversal during client-side recursive copy — CVE-2026-106552: client trusts server-supplied path components, the VPN-client-role-reversal axis again — on red-team infrastructure, a hostile SFTP/WebDAV endpoint a target employee connects *out* to writes outside the download dir.
- Plus certificate expiry mishandling in `ssh-keygen` (CVE-2026-106584) and unenforced max-packet-length check (CVE-2026-106585).

- Operator rules: (1) **audit SSH hardening by testing what each knob actually gates**, not by reading `sshd_config`/`authorized_keys` — on authorized engagements, enumerate forbidden-verb survivors past `restrict` (tunnel, agent-forwarding, port-forwarding variants, `permit-tunnel`) against your own test user; option-grant grammar has repeatedly been per-option, and the "catch-all" keyword lags new options. (2) Client-side trust: any automation or analyst that pulls from third-party SFTP/SCP endpoints should be treated as running a hostile-server protocol — test recursive-copy traversal only against your own listener.
- Version fingerprint: these are <10.6 fixes; `ssh -V` on targets and jump hosts is the whole triage.