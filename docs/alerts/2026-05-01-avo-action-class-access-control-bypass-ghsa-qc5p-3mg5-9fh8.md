# Avo action-class access control bypass (GHSA-qc5p-3mg5-9fh8)

**Signal:** GitHub Security Advisories updated **2026-05-01**. Avo versions before **3.31.2** could let an authenticated admin-panel user execute arbitrary `Avo::BaseAction` descendants through the wrong resource endpoint.

## What it is
Avo's `ActionsController` resolved the requested action by searching all `Avo::BaseAction` descendants for `params[:action_id]`. The lookup did not confirm that the action was registered for the current resource context.

That means a low-privilege authenticated user who can reach the Avo admin panel may be able to POST to an allowed resource action endpoint while naming a sensitive action class from another resource. If the action itself trusts the controller/resource gate, this can become cross-resource privilege escalation, unauthorized record mutation, or destructive operations against records the user should not control.

Affected package: `avo` RubyGem versions `< 3.31.2`.

Reference: <https://github.com/advisories/GHSA-qc5p-3mg5-9fh8>

## Triage
1. Inventory applications using Avo and confirm the installed `avo` gem version.
2. Prioritize internet-facing or broadly accessible admin panels, especially multi-tenant back offices.
3. Review custom Avo actions for sensitive effects: role changes, user/account mutation, billing changes, exports, deletes, archives, impersonation, and cross-tenant operations.
4. Check whether custom actions perform their own authorization on both the acting user and target record, instead of relying only on action registration.
5. Review recent admin audit logs for action names executed through unexpected resource routes.

## Mitigation
- Upgrade `avo` to **3.31.2** or later.
- Add explicit authorization inside high-impact action handlers, including target-record ownership/tenant checks.
- Treat resource registration as routing metadata, not the final authorization boundary.
- If immediate upgrade is blocked, temporarily disable or guard sensitive custom actions and add deny-by-default checks for unregistered resource/action combinations.

## Detection ideas
- Log `resource`, `action_id`, actor, target IDs, tenant/org, and request path for Avo actions.
- Alert when an action class associated with one resource is invoked through a different resource path.
- Hunt for low-privilege admin users invoking actions whose names imply admin, user-management, billing, export, delete, archive, or role changes.
- Compare action execution against expected UI exposure; suspicious API-only invocations deserve review.

## Durable lesson
Controller-level class lookup is an authorization boundary. Resolve privileged action classes only from the current resource's allowed action set, and make every high-impact action re-check actor, resource, tenant, and target record before it mutates state.
