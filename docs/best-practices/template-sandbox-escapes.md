# Template sandbox escapes (SSTI → RCE): how to contain the blast radius

Template engines are often used as “safe” renderers for emails, CMS pages, or user-customizable content. In practice, **many template “sandboxes” are bypassable**, and a template injection bug can become **remote code execution**.

This is true even when:

- the engine claims to sandbox
- you disable obvious dangerous functions
- you restrict imports/includes

## Core rule

**Do not render untrusted templates in-process.**

If users can edit templates (or template fragments), treat it like untrusted code execution and design accordingly.

## Safer designs (preferred)

### 1) Don’t accept templates; accept *data + a fixed template*

- user supplies variables (data)
- you render a fixed, developer-owned template

This eliminates SSTI at the root.

### 2) Use a constrained DSL instead of a general-purpose template language

Examples:

- “mustache-like” substitution only (`{{name}}`)
- strict allowlisted helpers
- no loops/conditions (or only heavily constrained versions)

### 3) Render in a separate, hardened worker

If you must accept user-authored templates:

- run rendering in a **separate process/container/VM**
- apply **resource limits** (CPU/time/memory/output size)
- drop privileges (no root)
- deny network egress unless required
- mount filesystem read-only (or minimal scratch dir)
- avoid passing secrets into the worker environment

## Defense-in-depth hardening checklist

### Restrict capabilities

- Disable/avoid:
  - reflection / method invocation primitives
  - dynamic evaluation features
  - file access helpers
  - “include” from arbitrary paths
  - access to runtime/environment objects

### Strict input boundaries

- Don’t allow raw template execution from URL params.
- Treat templates as content that must be stored, reviewed, and versioned.
- Add moderation/review for template changes where possible.

### Apply timeouts and output limits

Prevent:

- infinite loops
- quadratic expansions
- huge output generation (DoS)

### Monitoring

- log template compilation/render failures
- alert on unusual template edit activity
- detect “probing” behavior (repeated syntax errors, use of forbidden tokens)

## Testing / red flags

If the system supports user templates, look for:

- access to “context” objects that expose internals
- helpers that can read files, HTTP fetch, execute commands, or evaluate expressions
- tags/filters that allow reflection-like behavior
- template syntax that resembles Jinja/Jinjava, Twig, Velocity, Freemarker, etc.

## Trigger event

This page was prompted by advisories demonstrating **sandbox bypasses** in Jinja-like engines (e.g., Jinjava) where untrusted templates could be leveraged to reach arbitrary code execution.
