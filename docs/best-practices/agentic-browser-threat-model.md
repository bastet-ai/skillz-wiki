# Agentic browsers: threat model + isolation mitigations

Agentic browsers (browsers with an embedded AI agent that can *read content* and *take actions*) re-introduce familiar web security failure modes.

The key mistake is usually **missing isolation** between:

- Untrusted external content (webpages, PDFs, gists)
- The agent’s “chat context”
- Authenticated browsing sessions (cookies, local storage)
- Action-capable tools (open URLs, click buttons, fetch URLs)

When these zones are not isolated, prompt injection becomes the AI-era equivalent of **XSS/CSRF**.

## A simple threat model

### Trust zones

1. **Chat context**: conversation history + agent scratchpad/state.
2. **External network**: attacker-controlled webpages/docs.
3. **Browsing origins**: sites the user is authenticated to (banking, email, SaaS).
4. **Tooling / automation**: functions that can browse, click, download, and send requests.

### Common violation classes

- **Injection**: untrusted content adds instructions into the chat context.
- **CTX_IN**: sensitive data from authenticated origins enters the chat context.
- **REV_CTX_IN**: the agent modifies browsing origins using chat-derived content.
- **CTX_OUT**: chat-derived content leaks to external network via requests/side-channels.

If you allow **Injection + CTX_IN + CTX_OUT**, you should assume **cross-site data theft** is feasible.

## Practical attack patterns to expect

- **Prompt injection via rendered content**: hidden HTML, PDFs, gists, comments, DMs.
- **Session confusion**: attacker causes agent to open “magic links” and silently switch accounts.
- **Cross-site data exfiltration**: agent reuses cookies to pull private data, then leaks it.
- **History pollution / persistence**: agent adds attacker-controlled artifacts to history/state.

## Mitigations (high leverage)

### 1) Isolate tool browsing contexts from the user session

**Rule:** tools must not share cookies / local storage with the user profile.

- Run tool browsing in a separate profile/container.
- Treat all tool fetches as **unauthenticated by default**.
- Require explicit user re-auth (in the tool context) for privileged actions.

This blocks most CTX_IN and REV_CTX_IN paths.

### 2) Restrict tools by origin (extend Same-Origin Policy to agents)

- Track the set of origins that influenced the current chat context.
- If **multiple origins** are present, block action-capable tools (or require approval).
- If a **single origin** is present, restrict requests/actions to that origin.

**Implementation detail that matters:** origin/host allowlists must use **real URL parsing** and correct **hostname boundary checks** (e.g., `host == example.com` or `host.endswith(".example.com")`) — not naive string prefix checks.

This reduces CTX_OUT exfiltration risk.

### 3) Add a human-in-the-loop gate for risky actions

Gate actions that:

- Navigate to new domains
- Submit forms
- Download / upload files
- Send messages

Make the agent show the **exact tool inputs** it will use (not just a summary).

### 4) Split “read” vs “act” models (decouple content processing from task planning)

- Use a **quarantined** model to summarize untrusted content.
- Use a **privileged** model (with tools) that only consumes *trusted* user instructions.

Even a lightweight variant ("summarizer has no tools") meaningfully reduces blast radius.

## Operational notes

- Treat all untrusted content as potentially **hostile instructions**.
- Log tool actions for forensics (URLs, timestamps, tool inputs), but avoid logging secrets.
- Ensure the underlying browser engine is **patched quickly**; agentic forks tend to lag.

## References

- Trail of Bits: "Lack of isolation in agentic browsers resurfaces old vulnerabilities" (2026-01-13)
