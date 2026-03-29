# Channel Policy Enforcement Must Happen Before Enqueueing

**Date**: 2026-03-28  
**Status**: Durable guidance

Messaging and moderation systems should enforce mention, pairing, and reply policy before they enqueue an action that will be visible to users. If policy checks happen after the enqueue step, a bypass can cause messages, reactions, or verification notices to reach unintended recipients.

## What to enforce

- Check mention/DM policy before side effects.
- Validate pairing or conversation membership before sending.
- Apply the same authorization rules to all event sources.
- Treat reactions, verification prompts, and system notices as privileged actions.
- Make policy enforcement deterministic and centralized.

## What not to assume

- A reaction is “just a reaction” and therefore harmless.
- A verification notice can ignore the normal DM path.
- If one UI path is protected, every backend entry point is protected.

## Validation checklist

- Can the action be triggered without the required mention or pairing?
- Are all trigger paths using the same authorization gate?
- Is the visible side effect created only after checks pass?
- Are policy decisions logged for review?

## Typical failure mode

One event path skips the mention/pairing guard and still enqueues a user-visible system event. The fix is to enforce the policy at the boundary, not just in the presentation layer.
