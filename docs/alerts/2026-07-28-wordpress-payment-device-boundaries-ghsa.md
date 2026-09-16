---
title: WordPress role, nonce, payment-response, and device filesystem boundaries from late-July updates
---

# WordPress role, nonce, payment-response, and device filesystem boundaries from late-July updates

A late-July advisory wave yields eight durable operator checks: a low-role WordPress nonce disclosing connection material later accepted by a public administrator-login route, a frontend nonce treated as authorization for persistent WooCommerce options, an author-owned custom post exposing a role-assignment nonce and client-selected canonical role, contributor access accepted for site-wide event-payment settings, a successful payment response replayed across ticket orders, a public payment form whose hidden amount becomes the gateway amount, author-controlled post metadata reinterpreted as SQL during a later duplicate action, and unauthenticated virtual-filesystem access on SICK InspectorP6xx devices.

Sources:

- [GHSA-8fxc-wrxg-769w / CVE-2026-14328: Eazy Plugin Manager privilege escalation](https://github.com/advisories/GHSA-8fxc-wrxg-769w)
- [Eazy Plugin Manager 4.4.1 AJAX option handler](https://plugins.svn.wordpress.org/plugins-on-steroids/tags/4.4.1/plugins-on-steroids.php)
- [Eazy Plugin Manager 4.4.1 REST handlers](https://plugins.svn.wordpress.org/plugins-on-steroids/tags/4.4.1/libs/class.rest_api.php)
- [GHSA-qmvq-mp3j-6pvv / CVE-2026-13440: StoreGrowth stored popup markup](https://github.com/advisories/GHSA-qmvq-mp3j-6pvv)
- [GHSA-3368-w437-2p8j / CVE-2026-13110: StoreGrowth category-message write](https://github.com/advisories/GHSA-3368-w437-2p8j)
- [GHSA-xrhw-gwf7-m34v / CVE-2026-15411: StoreGrowth popup-option write](https://github.com/advisories/GHSA-xrhw-gwf7-m34v)
- [StoreGrowth 2.1.0 frontend nonce publication](https://plugins.svn.wordpress.org/storegrowth-sales-booster/tags/2.1.0/modules/bogo/includes/EnqueueScript.php)
- [StoreGrowth 2.1.0 popup AJAX handlers](https://plugins.svn.wordpress.org/storegrowth-sales-booster/tags/2.1.0/modules/sales-pop/includes/Ajax.php)
- [StoreGrowth 2.1.0 category-message AJAX handlers](https://plugins.svn.wordpress.org/storegrowth-sales-booster/tags/2.1.0/modules/bogo/includes/Ajax.php)
- [GHSA-f83j-v8r3-vfhv / CVE-2026-18029: pretix GiroCheckout payment-response replay](https://github.com/advisories/GHSA-f83j-v8r3-vfhv)
- [pretix security release 2026.6.1](https://pretix.eu/about/en/blog/20260728-release-2026-6-1/)
- [GHSA-2gm5-4hq3-g753: pretix quick-setup object authorization](https://github.com/advisories/GHSA-2gm5-4hq3-g753)
- [GHSA-5x3h-wq76-mxqx / CVE-2026-11841: SICK AppEngine Fileaccess exposure](https://github.com/advisories/GHSA-5x3h-wq76-mxqx)
- [SICK CSAF sca-2026-0010](https://www.sick.com/.well-known/csaf/white/2026/sca-2026-0010.json)
- [GHSA-fgx3-jj2q-3c9j / CVE-2026-12144: Wholesale for WooCommerce role assignment](https://github.com/advisories/GHSA-fgx3-jj2q-3c9j)
- [Wholesale for WooCommerce 2.0.5 request-role handler](https://plugins.svn.wordpress.org/woo-wholesale-pricing/tags/2.0.5/inc/class-wwp-wholesale-requests.php)
- [Wholesale for WooCommerce corrected request-role handler](https://plugins.svn.wordpress.org/woo-wholesale-pricing/trunk/inc/class-wwp-wholesale-requests.php)
- [GHSA-6p3r-44rr-gcj5 / CVE-2026-17166: Event Booking Manager site-wide payment settings](https://github.com/advisories/GHSA-6p3r-44rr-gcj5)
- [Event Booking Manager 5.3.7 payment-settings handler](https://plugins.svn.wordpress.org/mage-eventpress/tags/5.3.7/admin/settings/global/admin_setting_panel.php)
- [Event Booking Manager corrected payment-settings handler](https://plugins.svn.wordpress.org/mage-eventpress/trunk/admin/settings/global/admin_setting_panel.php)
- [GHSA-4hpv-v74p-q5cg / CVE-2026-1982: Persian Elementor ZarinPal amount manipulation](https://github.com/advisories/GHSA-4hpv-v74p-q5cg)
- [Persian Elementor 2.8.1 ZarinPal form](https://plugins.svn.wordpress.org/persian-elementor/tags/2.8.1/widget/zarinpal/zarinpal-button.php)
- [Persian Elementor 2.8.1 ZarinPal request and verification handler](https://plugins.svn.wordpress.org/persian-elementor/tags/2.8.1/widget/zarinpal/zarinpal-ajax.php)
- [Persian Elementor revision 3613858](https://plugins.trac.wordpress.org/changeset/3613858/persian-elementor)
- [GHSA-mjmr-35x5-p5hh / CVE-2026-16092: Improved Save Button second-order SQL injection](https://github.com/advisories/GHSA-mjmr-35x5-p5hh)
- [Improved Save Button 1.2.1 duplicate action](https://plugins.svn.wordpress.org/improved-save-button/tags/1.2.1/actions/class-lb-save-and-then-action-duplicate.php)
- [GHSA-5mvv-43fh-86fq / CVE-2026-13178: Eventin client-selected paid order status](https://github.com/advisories/GHSA-5mvv-43fh-86fq)
- [GHSA-vx7q-rhxw-6x3x / CVE-2026-13143: WP Travel unverified PayPal IPN](https://github.com/advisories/GHSA-vx7q-rhxw-6x3x)
- [GHSA-v6g6-7m7c-3mx6 / CVE-2026-15250: Appointment Booking client-selected approval status](https://github.com/advisories/GHSA-v6g6-7m7c-3mx6)
- [GHSA-9fxw-6x9j-x2gr / CVE-2026-12687: ProfileGrid privileged-group registration](https://github.com/advisories/GHSA-9fxw-6x9j-x2gr)
- [GHSA-5cfw-whc5-jqgh / CVE-2026-14356: FleekDash registration-to-account-update chain](https://github.com/advisories/GHSA-5cfw-whc5-jqgh)
- [GHSA-vm2x-vwh2-372v / CVE-2026-15255: RegistrationMagic OTP identity mismatch](https://github.com/advisories/GHSA-vm2x-vwh2-372v)
- [GHSA-49jm-q6q7-76gc / CVE-2026-11870: WP Ghost untrusted client-IP headers](https://github.com/advisories/GHSA-49jm-q6q7-76gc)
- [GHSA-qwc9-q2f8-q72q / CVE-2026-8457: WooCommerce Social Login Apple-token verification](https://github.com/advisories/GHSA-qwc9-q2f8-q72q)
- [GHSA-mxw9-rxrv-85f3 / CVE-2026-18352: User Access Manager attachment/path selector mismatch](https://github.com/advisories/GHSA-mxw9-rxrv-85f3)
- [GHSA-2cff-wc4f-2m48 / CVE-2026-13339: CubeWP SVG file-path handling](https://github.com/advisories/GHSA-2cff-wc4f-2m48)

The GitHub records were unreviewed when this page was written. The primary pretix release uses **CVE-2026-57532** for the quick-setup issue, while the initial GitHub record used **CVE-2026-18028** for substantially the same description. Preserve that discrepancy in evidence rather than treating the identifiers as interchangeable. Confirm the exact product slug, version, route, configuration, and fixed behavior before reporting.

!!! warning "Authorized validation only"
    Use disposable WordPress sites, synthetic users and roles, fake connection values, reversible payment-setting markers, test-mode ticket orders, mocked payment responses, local SQL recorders, and owned SICK lab devices with vendor-approved canary storage. Never mint or retain a production administrator session, promote a real account, alter a real store, send a payment to a live gateway, reuse live payment confirmations, extract database data, obtain unpaid real tickets or bookings, read form submissions or customer records, read device passwords, change production vision parameters, or place Lua code on a device.

## Build a boundary matrix first

| Surface | First attacker-controlled representation | Authority the server should derive | Safe proof |
| --- | --- | --- | --- |
| WordPress remote management | subscriber-visible nonce and option name | capability plus server-held connection secret | fake option values and a canary user |
| WooCommerce frontend AJAX | nonce published to anonymous visitors | authenticated role and explicit capability | reversible text-only option marker |
| Wholesale-request approval | request post, nonce, status, and role slug | request ownership plus role-promotion capability and server allowlist | synthetic author and non-privileged canary role |
| Event payment settings | authenticated AJAX action and settings fields | `manage_options` plus action-bound nonce | reversible confirmation-page/status markers |
| Ticket payment callback | successful status response | provider transaction bound to one order and amount | two mocked orders in test mode |
| ZarinPal payment request | public hidden `amount` field | server-stored widget price and selected product/quantity | local gateway recorder plus synthetic amount |
| Duplicate-post metadata | author-controlled `meta_key` stored first and interpolated later | parameterized metadata copy preserving exact value | query recorder and inert delimiter-shaped marker |
| Event quick setup | event ID and request timing | current user's organizer/event permissions | one reversible synthetic product marker |
| Device virtual filesystem | remote path selector | authenticated session and approved virtual root | pre-seeded non-sensitive canary file |
| Apple social login | public route proof plus decoded token email | verified Apple signature and claims bound to the configured client | invalid-signature synthetic token plus no-op session recorder |
| Protected attachment download | public attachment ID plus caller-selected file path | one canonical attachment object authorizing the exact file opened | two synthetic attachments and a read-path recorder |
| CubeWP SVG helper | public nonce and caller-selected icon URL/path | server-selected media object confined to an approved SVG root | sibling SVG-text canary and patched read recorder |

For every surface, preserve anonymous, low-role, expected-role, malformed-proof, wrong-object, and fixed-build controls. Stop at the first harmless marker that proves the crossed boundary.

## Eazy Plugin Manager: compose nonce scope, option scope, and login scope

The advisory describes a three-edge chain in versions through 4.4.1 when the remote-connection feature has populated its connection options:

1. admin-area assets expose a `pos` nonce to every logged-in admin-area user;
2. an AJAX handler verifies that nonce but accepts an arbitrary option name and returns `get_option()` data without a capability check; and
3. the public `epm/v1/admin/login` route authenticates using values from those options, then creates a session for the site's administrative email account.

The source confirms the important distinctions: the nonce proves only that WordPress issued a nonce to a logged-in user, the option selector determines which server state is disclosed, and the public route performs its own connection-key calculation before setting cookies. Do not collapse these into “nonce bypass.”

### Marker-only lab workflow

1. Install 4.4.1 on a disposable site. Create an administrator for setup and a separate subscriber canary.
2. Populate the plugin's remote-connection state with **fake** site and connection values. Record whether the feature is configured; the chain should fail closed when those values are absent.
3. Sign in as the subscriber and confirm whether plugin assets place the `pos` nonce on an admin-area page reachable to that role.
4. Call the option handler with a harmless custom option first. Compare an expected public option, the fake connection options, a nonexistent name, and an unrelated sensitive-looking name whose value is only a synthetic marker.
5. Record nonce acceptance and returned option name/type independently. Do not retrieve real salts, API keys, mail credentials, or user data.
6. Reproduce the route's authentication calculation offline using only the fake connection values. Retain a hash of the test input tuple, not the raw values.
7. In an instrumented lab, replace the administrative-email target with a disposable canary user or intercept `wp_set_auth_cookie()` with a counter. Send the valid fake proof and malformed, reordered, stale, and random controls.
8. If an end-to-end cookie check is required, use only the canary account and a harmless identity endpoint, then immediately invalidate the session.
9. Repeat on the fixed build and verify capability enforcement, constrained option names, and rejection at the public login route.

A bounded positive result is **subscriber receives nonce -> arbitrary-option handler returns configured fake connection state -> derived proof reaches public login handler -> canary cookie setter executes**. Do not demonstrate takeover of a real administrator. Report each edge separately if the full chain is not reproduced.

## StoreGrowth: a public nonce is not an authorization decision

StoreGrowth 2.1.0 creates `ajd_protected` and publishes it in the frontend `bogo_save_url` object. The same token is accepted by AJAX handlers registered through `wp_ajax_nopriv_*`. Source review shows `create_popup()` writes `spsg_popup_products`, while `bogo_category_msg_create()` mutates category-message settings. The associated XSS record adds a rendering question, but persistent option control and browser execution remain separate claims.

### Anonymous option-write matrix

1. Install 2.1.0 in a disposable WooCommerce site with no customer data and script execution instrumented to a harmless counter.
2. Fetch a normal public storefront page with no cookies and record whether `bogo_save_url.ajd_nonce` is present.
3. Exercise the relevant AJAX action with missing, random, stale, logged-out, public-page, subscriber, and administrator-issued nonce values.
4. Write only a unique plain-text marker into a disposable popup or category-message fixture. Read it back through the plugin UI or option API, then restore the original value.
5. Repeat with a second anonymous browser to determine whether the nonce is session-bound or simply reusable by any visitor during its validity window.
6. For the stored-markup claim, use a harmless element carrying a unique `data-*` attribute. Record storage, rendered context, sanitizer output, and DOM appearance separately; do not use script, event-handler, external-resource, or navigation payloads.
7. Confirm whether the fixed version rejects anonymous requests before any option write and whether rendering encodes the marker.

The decisive authorization evidence is **anonymous public page yields nonce -> `wp_ajax_nopriv_*` accepts it -> persistent synthetic option changes without a capability decision**. The decisive rendering evidence additionally requires **stored marker reaches the intended frontend sink after the application's normal render path**. Do not call a changed database option XSS by itself.

Generalize this check to any WordPress plugin that localizes nonces into public JavaScript and then registers mutating `nopriv` handlers. Inventory the handler's capability checks and server-owned object scope; nonce verification alone is CSRF resistance, not proof that the caller may perform the action.

## Wholesale for WooCommerce: compose post ownership, nonce visibility, and role selection

The 2.0.5 source registers `wwp_requests` with the ordinary `post` capability model. Its `save_requests_meta()` handler verifies `request_user_role_nonce`, but does not require `manage_options` or `promote_users`; it sanitizes the submitted `user_role_set` as text and passes that value to `WP_User::add_role()`. The advisory's important precondition is that an author who owns a wholesale-request post can reach its edit screen and nonce. This is not a nonce bypass: the valid nonce is available because the custom post type grants the wrong principal access, and the later handler mistakes a client-selected role slug for policy.

The corrected source provides three independent rejection controls worth testing: it maps the custom post type's edit/publish/delete capabilities to `manage_options`, checks `manage_options` in the save handler, and allowlists `user_role_set` against registered wholesale-role taxonomy slugs before calling `add_role()`.

### Marker-only role-assignment workflow

1. Install 2.0.5 on a disposable WordPress site. Create a synthetic author and a harmless custom canary role with no administrative capabilities. Keep the setup administrator in a separate browser.
2. Create a wholesale request through the normal registration flow for the author. Confirm the resulting request post's `_user_id`, author/owner, status, and edit-screen reachability without collecting another user's request.
3. As the author, record whether the request edit screen renders `request_user_role_nonce`. Preserve only nonce provenance and a hash; do not retain the raw value.
4. Capture the ordinary save request. Replay omitted, random, stale, valid-own-request, valid-foreign-request, and fixed-build nonce controls while varying `user_status` and `user_role_set` independently.
5. First request only the harmless canary role. Read back the target user's canonical roles and capabilities, then restore the original role. Do not request `administrator` or any role that can install plugins, edit users, access secrets, or execute code.
6. Instrument `WP_User::add_role()` if stronger sink evidence is needed. A call counter plus the submitted canary slug proves role-selector reachability without granting privilege.
7. Repeat on the corrected build and verify all three controls separately: the author cannot edit the request post, the handler rejects callers without `manage_options`, and an unexpected role slug is replaced or rejected before the role sink.

A bounded positive result is **author owns request post -> edit screen yields valid nonce -> save handler accepts client-selected canary role -> canonical role state or instrumented `add_role()` sink changes without promotion authority**. Report the post-ownership and nonce preconditions; do not generalize this to anonymous or subscriber access.

This pattern generalizes to plugins that use custom post types as approval queues. Test the post type's mapped capabilities, nonce visibility, target-user binding, submitted role/capability allowlist, and sink-level promotion check as separate edges.

## Event Booking Manager: distinguish content editing from site-wide payment authority

Event Booking Manager 5.3.7 registers the authenticated `mep_save_payment_settings_modal` AJAX action. Its handler accepts callers with either `manage_options` **or** `edit_posts`, has no action nonce check, and updates the global `payment_setting_sec` option. That option controls WooCommerce payment enablement, checkout redirects, login and billing requirements, confirmation-page selection, and ticket-confirming order statuses. A contributor's ability to edit content is therefore being reused as authority over every event's payment workflow.

The corrected source adds `check_ajax_referer( 'mep_save_payment_settings', 'nonce' )` and narrows the capability decision to `manage_options`. Treat both controls independently: a nonce fixes request provenance/CSRF exposure, while the capability check decides whether the authenticated principal may change global payment state.

### Reversible global-setting matrix

1. Install 5.3.7 in a disposable WooCommerce/Event Booking Manager lab with no live gateways, customers, orders, or tickets. Snapshot `payment_setting_sec` and create a synthetic contributor plus an expected administrator.
2. Capture the normal `mep_save_payment_settings_modal` request. Exercise anonymous, subscriber, contributor, editor, and administrator identities with omitted, random, and valid action-nonce variants.
3. Change only benign values: a disposable confirmation-page ID and a synthetic, non-production order-status marker. Avoid enabling gateways, changing checkout authentication, or selecting statuses used by real orders.
4. Read the option back through an administrator-side lab harness, record the acting user and before/after hashes, then restore the snapshot immediately.
5. Test omitted fields as well as supplied fields because the affected handler assigns defaults to absent values; one partial request may change more global keys than it names.
6. Repeat on the corrected build. Confirm that a valid nonce from a low-role context still fails `manage_options`, and that an administrator request without the action-bound nonce fails before `update_option()`.

The decisive evidence is **`edit_posts`-only principal -> authenticated AJAX action -> global `payment_setting_sec` canary changes without `manage_options`**. A `200` or JSON success response without persisted option evidence is insufficient. Report cross-event/global scope separately from checkout, ticket, or revenue impact; do not process an order to inflate the claim.

## Persian Elementor: bind a public payment request to server-owned price state

Persian Elementor 2.8.1 renders the configured ZarinPal total into a hidden `amount` input. The public `zarinpal_payment_request` AJAX handler verifies the frontend nonce, then derives its transaction amount from that submitted field. It stores the same amount in transient transaction state, passes it to the payment-request helper, and later uses the stored value for provider verification. The nonce therefore proves request provenance but does not bind the submitted amount to the widget's configured price.

The durable check is broader than one gateway: whenever a storefront renders amount, currency, product, discount, quantity, or merchant fields into the browser, determine whether the server reconstructs the payable tuple from authoritative catalog/order state before both **payment creation** and **payment verification**.

### Local gateway-recorder workflow

1. Install 2.8.1 on a disposable WordPress/Elementor site. Configure one ZarinPal widget with a synthetic product and amount; use a fake merchant identifier and prevent outbound DNS/network access.
2. Capture the public form and record the displayed total, hidden amount, nonce provenance, callback URL, and product description. Use only the normal anonymous page context.
3. Replace the ZarinPal request helper with a local recorder that accepts no payments and returns a fixed canary authority. Instrument transient writes as well. Do not redirect to or contact the real provider.
4. Replay the request with the expected amount, a different positive canary amount, zero, negative, fractional, oversized, omitted, and duplicate amount fields. Keep the values non-monetary inside the recorder.
5. For each case, record the raw submitted representation, integer/conversion result, transient amount, helper amount, and response state. Vary product/description fields separately so amount binding is not confused with descriptive metadata.
6. Invoke the callback path only through a stub verification helper. Confirm whether it verifies the attacker-selected stored amount rather than independently recovering the configured widget price.
7. Repeat against the corrected revision and require the server to derive the expected amount from server-owned widget/product state before the request helper and to bind callback verification to that same transaction tuple.

A bounded positive result is **public form exposes reusable request proof -> modified hidden amount -> local request recorder receives the modified amount -> transaction state and stub verification preserve it without a server-side price lookup**. This proves amount authority drift; it does not prove that a live payment completed, goods were delivered, or a specific monetary loss occurred.

Preserve unit conversions explicitly. The affected handler divides the submitted value before its helper restores the provider-facing unit, so evidence should show browser value, normalized internal value, and recorder value rather than assuming all three numbers use the same currency unit.

## Improved Save Button: replay stored metadata through a later SQL sink

Improved Save Button 1.2.1 illustrates a second-order SQL injection boundary. The duplicate action first reads `meta_key` and `meta_value` rows for an editable source post. It escapes the values but interpolates each metadata key into a hand-built `INSERT ... SELECT` statement joined with `UNION ALL`, then passes the assembled string to `$wpdb->query()`. The attacker's first action stores a metadata key through an otherwise ordinary post-edit path; interpretation occurs later when an authorized **Save and Duplicate** operation copies that stored row.

This differs from direct request-to-query injection. Map four moments independently: **write principal -> stored bytes -> later trigger principal -> constructed SQL grammar**. A scanner that mutates only the duplicate request may miss the actual controllable input.

### Recorder-only second-order harness

1. Install 1.2.1 in a disposable WordPress database containing only synthetic posts and metadata. Create an author-owned source post and a separate clean control post.
2. Confirm which supported custom-field, REST, XML-RPC, importer, or plugin path lets that author create a metadata key on their own post. Preserve the exact capability and API used; do not assume every WordPress role can set arbitrary keys.
3. Store an inert delimiter-shaped canary key containing a quote marker and unique token, plus a plain control key. The marker must not contain a second SQL statement, comment sequence, data-extraction expression, timing function, or destructive verb.
4. Replace or wrap `$wpdb->query()` in the lab so the duplicate action records the final SQL string and returns without executing it. Trigger **Save and Duplicate** through the normal UI as the same author and, separately, as an expected editor.
5. Compare the stored key bytes, values returned by the first metadata query, final recorded SQL, and tokenized SQL parse. The key should remain one bound data value; if the marker changes quote/token boundaries in the recorded grammar, the sink is reachable.
6. Exercise controls for a plain key, delimiter-shaped metadata **value**, protected-key prefix, metadata belonging to another author, a post the caller cannot duplicate, and no metadata. This separates key handling, value escaping, object authorization, and trigger reachability.
7. Repeat on a corrected build or locally parameterized implementation. Require metadata copying through WordPress APIs or bound placeholders, with both key and value remaining data in the parser output.

The safe positive result is **authorized author stores inert metadata key on own post -> later duplicate action reads it -> recorder shows the key crossing a SQL token boundary**. Do not execute the malformed query against even a lab database merely to prove disclosure. Query construction plus a parser diff and the fixed control provide stronger, less destructive evidence.

## pretix: bind provider responses to one payment object

The primary pretix release says `pretix-girosolution` before 1.0.1 accepted a successful GiroCheckout status response from one payment for a different payment. That is a transaction-binding failure: authenticity of a provider response is insufficient when the response is not bound to the local order, payment ID, amount, currency, merchant context, and lifecycle state.

### Two-order replay harness

1. Use a disposable pretix organizer, the affected enterprise plugin, and a mocked or provider-approved test-mode GiroCheckout endpoint.
2. Create orders A and B with distinct marker products and amounts. Do not issue scannable real-event tickets.
3. Complete A through the mock and capture the normalized status fields consumed by pretix. Redact provider credentials and replace identifiers with stable hashes in retained evidence.
4. Replay A's response at B's callback/status transition while varying one field at a time: local payment ID, provider transaction ID, order, amount, currency, merchant account, and response timestamp.
5. Record the state transition for both orders and whether a ticket artifact is generated. Configure generated artifacts as invalid lab markers that cannot pass a production scanner.
6. Add duplicate delivery to A, out-of-order pending/success events, expired responses, and an already-refunded order as negative controls.
7. Repeat against `pretix-girosolution` 1.0.1 and confirm that A's authentic response cannot change B.

A valid result is **authentic success for synthetic payment A -> replay against B -> B becomes paid or receives a lab ticket without its own provider transaction**. Do not complete a live charge, transfer a real ticket, or test another organizer.

## pretix quick setup: test temporal and parent-object authorization together

The quick-setup issue is narrow but reusable: the primary source requires a user with limited permissions in the same organizer, an event that is still completely unconfigured, and a well-timed request. Treat organizer membership, event permission, event setup state, and timing as independent preconditions.

1. Create two organizers and three synthetic events: one unconfigured target, one configured control, and one event in another organizer.
2. Give user A read-only access where required and no configuration permission. Keep a separate expected-role operator.
3. Capture the normal quick-setup request and replay it with omitted, own-event, read-only target, configured target, and foreign-organizer event IDs.
4. Add a synchronization barrier in the lab so the request can be sent before, during, and after the legitimate setup transition.
5. Request only one reversible marker product or quota. Do not connect a real Stripe account or change bank-transfer details.
6. Verify final state through the owning operator, restore the marker, and compare fixed pretix releases 2026.6.1, 2026.5.4, or 2026.4.6.

Report the exact permission, parent organizer, target event state, and timing window. A static endpoint response without an unauthorized persisted marker is not enough.

## SICK InspectorP6xx: confine virtual-filesystem validation to canaries

SICK's CSAF identifies remote access to unintended internal virtual-filesystem paths through the SOPAS `FileSystemAccess` method. It lists InspectorP61x and P62x firmware below 5.4.0 as affected and 5.4.0 as fixed. InspectorP63x, P64x, and P65x are listed as affected across all firmware versions in that advisory. The record covers query and modification of internal storage, configuration files, and application directories; the adjacent GitHub description mentions customer-defined passwords and possible Lua execution, but those higher-impact claims must not be tested on production devices.

### Read/write boundary workflow

1. Confirm written authorization, exact Inspector model/SKU, firmware, network path, and whether SOPAS FileSystemAccess is reachable. Package presence or a web banner is not enough.
2. Use an isolated owned device. Through supported local tooling, pre-seed one non-sensitive canary in a vendor-approved application-data location and hash its contents.
3. From the remote test segment, compare unauthenticated, malformed-session, low-role, and expected authenticated requests for an allowed canary path, a nonexistent path, and one known internal path represented only by a fake lab marker.
4. Stop if the canary is returned without authentication. Do not request device parameter files, passwords, certificates, logs, customer images, or arbitrary system paths.
5. If write validation is explicitly approved, modify only a disposable canary file and verify its hash. Do not alter configuration, startup state, inspection jobs, firmware, or application code.
6. Do not upload Lua. If execution reachability matters, use static route/source evidence or an instrumented vendor lab where the application loader is replaced by a no-op counter.
7. Repeat on P61x/P62x firmware 5.4.0. For P63x/P64x/P65x, report the vendor's all-version affected status and do not infer a fixed build.

A safe positive result is **network-reachable FileSystemAccess -> no authenticated identity -> pre-seeded virtual-filesystem canary read or marker-only write outside the intended public root**. Separate unauthenticated read, write, configuration impact, application loading, and code execution in the final report.

## July 30 follow-up: bind public workflow state to server authority

The next WordPress advisory wave adds three related workflow checks. Eventin before 4.1.16 accepts a client-selected order status while creating an order; Appointment Booking Plugin before 5.6.8 lets the public booking funnel set an approval-status field; and WP Travel before 11.8.1 accepts a PayPal Instant Payment Notification without completing the provider post-back verification handshake. In each case, a browser or callback supplies a state label that the application later treats as an authoritative business transition.

### State-transition recorder

1. Use a disposable site with fake events, trips, appointments, customers, prices, and payment-provider credentials. Disconnect outbound networking.
2. Capture one normal request for each affected flow. Record the public fields separately from server-owned catalog, booking, order, and payment state.
3. Replace gateway verification, ticket issuance, email, webhook, and fulfillment sinks with local counters. No real booking or deliverable should be created.
4. For Eventin and Appointment Booking, vary status/approval fields through omitted, expected-pending, alternate valid, unknown, duplicate, and case-changed representations. Preserve the raw request and canonical persisted state.
5. For WP Travel, use a local PayPal recorder. Send missing, malformed, duplicated, and synthetic-success IPNs; record whether the plugin performs a post-back verification and binds receiver, merchant, amount, currency, booking ID, transaction ID, and lifecycle state before mutation.
6. Exercise replay, wrong-booking, wrong-user, stale, already-paid, and already-cancelled controls. Repeat on fixed builds.

The safe positive is **anonymous input supplies status or callback claim -> no server-owned transition/verification decision occurs -> synthetic order or booking reaches a paid/approved marker state**. Do not contact PayPal, reserve inventory, issue a ticket, or describe the result as financial loss without a separately authorized end-to-end proof.

## July 30 follow-up: separate registration eligibility from role and target identity

ProfileGrid before 5.9.9.8 reportedly lets an anonymous registration select a privileged group whose configured role may be administrator. FleekDash V2 through 2.6.2.2 reportedly exposes a registration route that creates a subscriber and returns a REST nonce even when normal registration is disabled, after which an account-update path can overwrite another user's email and password. RegistrationMagic before 6.0.9.4 reportedly accepts an OTP cookie without binding it to the identity whose submission is requested.

These are three different authorization edges:

| Edge | Caller proof | Missing server binding | Canary-only evidence |
| --- | --- | --- | --- |
| ProfileGrid registration | anonymous form/nonce | public-eligible group and server-chosen non-privileged role | harmless canary group and role |
| FleekDash bootstrap | newly created subscriber and returned nonce | registration policy, target user, and account-update authority | instrumented update sink targeting a second canary |
| RegistrationMagic retrieval | OTP cookie | OTP subject, requested identity, form, and submission owner | two synthetic identities and marker-only submissions |

### Two-identity lab matrix

1. Create canary users A and B, a public group, and a harmless restricted group mapped only to a custom role with no administrative capabilities. If the affected logic requires an administrator-mapped group, instrument `set_role()`/`add_role()` and stop at a call counter rather than creating that mapping.
2. For ProfileGrid, compare omitted group, public group, restricted group, nonexistent group, duplicate group parameters, and fixed-build behavior. Record the server-selected canonical role without granting privilege.
3. For FleekDash, test registration with site registration enabled and disabled. Hash any returned nonce, then replay the account-update request against self, B, a nonexistent ID, and an instrumented administrator target. The update sink must remain no-op for foreign targets.
4. For RegistrationMagic, issue separate short-lived OTPs for A and B. Cross the A cookie with B's identity, form, and submission identifiers one field at a time. Return only synthetic marker IDs, never submission bodies.
5. Invalidate all canary sessions and OTPs after testing. Repeat every matrix on a corrected release.

Report **anonymous group selection**, **self-provisioned nonce**, **foreign account-update sink reachability**, and **cross-identity OTP acceptance** separately. Do not create an administrator, change a real email/password, or read personal form data.

## July 30 follow-up: test client-IP provenance as a proxy chain

WP Ghost before 7.0.05 reportedly trusts client-IP HTTP headers without proving that they came from an approved reverse proxy. That can affect its own brute-force controls and match a hardcoded allowlisted range. This is a hop-by-hop identity issue, not merely “IP spoofing.”

1. Reproduce the deployed edge chain in a lab: direct client, approved proxy, WordPress origin, and the plugin. Give each hop a distinct synthetic address.
2. Record which headers each proxy strips, appends, or overwrites and which address the plugin finally chooses.
3. Test direct requests with `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, duplicate headers, comma lists, quoted forms, whitespace, IPv4-mapped IPv6, and malformed values. Use only canary addresses.
4. Exercise one harmless plugin decision behind counters: allowlist match and brute-force-attempt bucket. Do not submit password guesses or target WordPress core authentication.
5. Require the fixed control to trust forwarding headers only when the immediate peer is an explicitly configured proxy and to choose the client hop through one documented canonicalization rule.

A bounded positive is **untrusted direct peer supplies forwarding header -> plugin selects attacker-controlled canary address -> allowlist or rate-bucket decision changes**. Do not infer bypass of a WAF, upstream proxy, WordPress core login control, or another security plugin.

## July 31 follow-up: authentication proofs, workflow authority, and artifact exposure

The July 31 unreviewed feed adds six durable WordPress checks. Sources: [Realtyna authenticated upload GHSA-2982-9p75-vfp8](https://github.com/advisories/GHSA-2982-9p75-vfp8), [Realtyna static-credential upload GHSA-cfr3-ggcx-jjf3](https://github.com/advisories/GHSA-cfr3-ggcx-jjf3), [FlxWoo payment-state GHSA-j2wf-m8xp-xm7q](https://github.com/advisories/GHSA-j2wf-m8xp-xm7q), [ShopMonitor trusted-source GHSA-g4w8-444w-x9q8](https://github.com/advisories/GHSA-g4w8-444w-x9q8), [miniOrange 2FA GHSA-24j9-5c5r-9c88](https://github.com/advisories/GHSA-24j9-5c5r-9c88), [Demi backup GHSA-q89r-49r9-5hmx](https://github.com/advisories/GHSA-q89r-49r9-5hmx), and [Kirki stored-deserialization GHSA-rpvq-6gf9-58vg](https://github.com/advisories/GHSA-rpvq-6gf9-58vg). Confirm the exact plugin slug, version, reachable function, and corrected behavior before reporting.

### Static plugin proof must not become installation-wide authority

Realtyna illustrates two paths into the same file sink: subscriber-reachable key retrieval plus a weakly gated import route, and a public I/O endpoint whose API values are reportedly seeded identically across installations. In a disposable site, replace the upload/move sink with a recorder and use a benign GIF-like marker carrying a non-executable extension.

1. Compare anonymous, subscriber, and administrator contexts for key retrieval, REST import, and public I/O route families.
2. Test generated per-installation fake credentials against static migration-seeded fake credentials. Never publish or replay the vendor defaults.
3. Record authentication proof acceptance separately from extension/content validation and final public-path selection.
4. Stop when the recorder receives the benign marker and proposed canonical path. Do not upload PHP, probe a real media library, or request execution.

The safe positive is **public or low-role caller -> reusable installation-independent proof or insufficient route authorization -> file recorder accepts attacker-selected bytes/path**. “Upload returned 200” is insufficient, and code execution remains unproven without a separately authorized executable sink—which this workflow deliberately avoids.

### Bind 2FA to the server-held subject secret

Create users A and B with disposable passwords and TOTP seeds. Intercept the final session-creation sink. For B's login, cross server-held seed B with a caller-supplied seed or provisioning value controlled by A, then submit an OTP generated only from A's value. Exercise missing, malformed, expired, replayed, wrong-user, and fixed-build controls.

The proof is **B's valid first factor -> OTP checked against attacker-supplied material rather than B's enrolled server secret -> no-op session sink for B increments**. Do not target an administrator, preserve QR/provisioning URIs, or create a live privileged session.

### Bind payment and email-routing transitions to server authority

- **FlxWoo:** replace the payment provider with a local recorder and fulfillment with a counter. Submit paid, unpaid, unknown, wrong-order, replayed, and malformed checkout-session states. The counter must move only after server-to-provider verification binds payment status, merchant, amount, currency, order, and transaction ID.
- **ShopMonitor:** reproduce direct client, approved proxy, and origin hops. Supply forwarding/trusted-source headers only with canary addresses and replace email delivery with a recorder. Trigger password reset only for a disposable user. A positive requires an untrusted direct request to satisfy source trust and change the recorder destination; do not deliver mail or take over an account.

### Treat backups and stored objects as two-stage boundaries

- **Demi backup exposure:** create a synthetic backup containing only a unique marker, record its generated URL, then test anonymous access during and after export. Compare predictable-name guesses, directory listing disabled, expired/removed artifact, and fixed-build controls. Stop at the marker; never download a real database, hashes, configuration, or media.
- **Kirki stored deserialization:** store an inert serialized object whose permitted test class only increments a recorder when instantiated. Capture write principal, stored bytes, later administrator-review trigger, allowed-class decision, and recorder event separately. Use no magic method that executes commands, reads files, makes network requests, or mutates application state.

These are compound chains. Public artifact naming does not prove sensitive content unless the synthetic marker is returned; attacker-controlled storage does not prove object injection until the later deserializer instantiates the inert class.

## July 31 follow-up: transaction proofs and unauthenticated REST mutation

Three adjacent plugin records add reusable object-proof and route-authorization checks:

- [Fluent Forms GHSA-gx6f-fm4p-x72r / CVE-2026-17567](https://github.com/advisories/GHSA-gx6f-fm4p-x72r) says payment receipt lookup accepts a bounded, guessable transaction hash derived from observable submission/form/time context;
- [MailerPress GHSA-gjcp-gv56-hccw / CVE-2026-18437](https://github.com/advisories/GHSA-gjcp-gv56-hccw) says `mailerpress/v1/contact` permits unauthenticated contact updates through 1.5.0; and
- [MailPress GHSA-vfgx-g9m5-wfgv / CVE-2026-18436](https://github.com/advisories/GHSA-vfgx-g9m5-wfgv) says the campaign revision-restore route was registered without a permission callback through 1.5.0.

The GitHub records were unreviewed at scan time. Confirm the exact plugin slug—the records use both **MailerPress** and **MailPress**—version, route registration, identifier construction, and corrected behavior before reporting.

### Fluent Forms: measure proof entropy without collecting receipts

Use a disposable site containing only two synthetic forms, submissions, transactions, and payment receipts. Replace receipt rendering with a recorder that returns the matched canary transaction ID and no customer fields.

1. Create transactions A and B with distinct marker amounts/statuses and record the server-side inputs used to construct their public transaction proofs.
2. Capture A's legitimate receipt URL. Change submission ID, form ID, transaction timestamp component, and proof one field at a time.
3. Reconstruct the candidate space only for B's synthetic tuple. Rate the local function or recorder, not a network endpoint, and record candidate count, alphabet, entropy assumptions, and first match.
4. Exercise random, expired, wrong-form, wrong-submission, wrong-time-window, cross-session, and fixed-build controls.
5. Stop when B's canary transaction ID reaches the recorder. Do not render or retain names, email addresses, billing addresses, order items, payment methods, or any production receipt.

The bounded positive is **anonymous caller plus observable synthetic object context -> practical search over transaction proof -> foreign canary transaction reaches the receipt-selection sink**. Do not call the proof predictable solely because it is short; demonstrate the effective candidate space under the application's actual construction and validation rules.

### MailerPress/MailPress: inventory permission callbacks and object binding

Create two contacts and two campaigns owned by a disposable administrator. Campaign A should have two plain-text revisions; campaign B is the foreign-object control. Intercept contact writes and campaign content writes with reversible recorders where possible.

| Route | Anonymous | Low role | Expected manager | Required secure decision |
| --- | --- | --- | --- | --- |
| `mailerpress/v1/contact` | reject | reject unless explicitly delegated | update in-scope canary | authenticate, check capability, bind contact ID and writable fields |
| campaign restore-revision route | reject | reject unless explicitly delegated | restore revision belonging to campaign | authenticate, check campaign capability, bind revision to parent campaign |

1. Enumerate the WordPress REST route definitions and capture `permission_callback`, accepted methods, argument schema, and handler names. Source evidence is useful, but retain a request-to-sink control as well.
2. For contact update, test omitted ID, own canary, foreign canary, nonexistent ID, duplicate ID, and immutable-looking fields. Change only a reversible marker field; never use a real subscriber record or email address.
3. For revision restore, cross campaign A with A's revision, campaign A with B's revision, campaign B with A's revision, nonexistent IDs, and an already-current revision. Instrument the content assignment sink or use plain-text markers only.
4. Record authentication, capability decision, canonical object lookup, parent-child binding, before/after marker hashes, and response independently.
5. Restore all canaries and repeat on a corrected build.

The safe positives are **anonymous REST request -> contact write recorder accepts a foreign canary ID** and **anonymous REST request -> revision restore changes a synthetic campaign without a capability decision**. A route visible in the REST index or a missing callback in source is not by itself proof of mutation. A valid revision must also belong to the selected campaign; otherwise report parent-child authorization drift separately.

## August 1 follow-up: plan roles, attachment paths, and structural markup allowlists

Three WordPress plugin records add reusable composition checks:

- [Subscriptions for WooCommerce GHSA-x6w6-m8vc-m6cp / CVE-2026-15414](https://github.com/advisories/GHSA-x6w6-m8vc-m6cp), with the [2.0.0 plan save handler](https://plugins.svn.wordpress.org/subscriptions-for-woocommerce/tags/2.0.0/includes/membership/class-wps-membership-plan-cpt.php);
- [Bit Integrations GHSA-j262-2rh9-xjv4 / CVE-2026-15006](https://github.com/advisories/GHSA-j262-2rh9-xjv4), with the [2.9.0 mail attachment handler](https://plugins.svn.wordpress.org/bit-integrations/tags/2.9.0/backend/Actions/Mail/MailController.php) and [Contact Form 7 trigger](https://plugins.svn.wordpress.org/bit-integrations/tags/2.9.0/backend/Triggers/CF7/CF7Controller.php); and
- [SendPulse Email Marketing Newsletter GHSA-5jrx-957p-3f93 / CVE-2026-13362](https://github.com/advisories/GHSA-5jrx-957p-3f93), with the [2.2.5 form-meta writer](https://plugins.svn.wordpress.org/sendpulse-email-marketing-newsletter/tags/2.2.5/inc/class-senpulse-newsletter-forms.php) and [shortcode renderer](https://plugins.svn.wordpress.org/sendpulse-email-marketing-newsletter/tags/2.2.5/inc/class-senpulse-newsletter-shortcodes.php).

The records were unreviewed at scan time. Confirm the exact free/Pro plugin combination, configured integration flow, custom-post capability mapping, reachable render path, and corrected behavior before reporting.

### Compose content capabilities with delayed role assignment

Subscriptions for WooCommerce 2.0.0 registers `wps_membership_plan` with the ordinary `post` capability model. Its plan save handler accepts a valid plan nonce plus `edit_post`, sanitizes `_wps_plan_user_role` as a key, verifies only that the slug names a registered role, and stores it. The advisory says the Pro companion later reads that meta and applies the role during membership lifecycle events. A disabled role selector in the browser is not a server policy, and “registered role” is not a safe privilege allowlist.

1. Use a disposable site with the exact affected free/Pro combination, a synthetic contributor, and a harmless custom role with no administrative capabilities. Replace the Pro role-application sink with a recorder when possible.
2. Determine whether the contributor can create or edit a membership-plan post and obtain the plan nonce. Preserve nonce provenance and a hash, not the token.
3. Capture an ordinary plan save, then vary only `_wps_plan_user_role`: omitted, harmless custom role, nonexistent slug, expected membership role, and a privileged-looking slug sent only to a recorder that rejects before mutation.
4. Trigger each configured purchase, subscription, auto-enrolment, expiry, and removal lifecycle path using synthetic users and products. Record plan ID, canonical stored slug, lifecycle event, target canary user, and the argument reaching `add_role()` or its equivalent.
5. Repeat on the corrected build. Require a plan-management capability separate from generic content editing and a server-side allowlist containing only purpose-built membership roles.

The bounded positive is **content-editing principal -> editable plan plus valid nonce -> caller-selected harmless role persists -> later membership event reaches the role-assignment recorder without promotion authority**. Do not request `administrator`, grant capabilities, buy a real product, or create a privileged session. Report edit-screen reachability, persistence, and delayed role application as separate edges.

### Trace public form fields into mail attachment paths

Bit Integrations 2.9.0 merges Contact Form 7 posted data with uploaded-file values, then executes configured flows. Its mail action treats the configured attachment selector as a key into that field map; `processAttachment()` accepts each readable path and forwards it to `wp_mail()` without a visible allowed-root check. This is a configured chain: anonymous form submission alone is not enough unless an attacker-controlled field is selected as the mail attachment input and survives into the action.

1. Build a disposable WordPress/Contact Form 7/Bit Integrations site with one public canary form and a mail flow whose transport is replaced by an attachment-path recorder. Disable real email delivery.
2. Seed a normal uploaded-file canary inside the expected temporary upload root and a second plain-text canary in a disposable sibling directory. No WordPress configuration, keys, user data, logs, or host files should exist in the lab.
3. Record the configured attachment field name. Submit expected upload metadata, a plain field containing the sibling canary path, relative and absolute benign path forms, a nonexistent path, a directory, a symlink to an in-root canary, and a symlink to the sibling canary. Change one representation at a time.
4. Intercept `wp_mail()` before it opens or sends attachments. Capture only the canonical paths proposed by the plugin and return a synthetic success response; do not attach, copy, or email the sibling file.
5. Establish controls with no matching flow, a flow whose attachment selector names only the real upload field, authenticated-only form access, unreadable canaries, and the corrected plugin.

A safe positive is **anonymous synthetic submission -> configured attachment field -> readable sibling-canary path reaches the mail attachment recorder outside the approved upload root**. A public form, readable local path, or mail-flow configuration by itself is insufficient. Do not use traversal to read content; path selection plus canonical-root evidence proves the boundary.

### Validate the whole markup tree, not one approved child

SendPulse 2.2.5 stores raw `_sp_form_code` for users who can edit a `sendpulse_form`. The shortcode renderer parses that string, verifies that the DOM contains exactly one `script` whose host and attributes are allowed, then returns the **entire original string** unchanged. The structural mismatch is durable: a validator approves one descendant while the renderer trusts the complete container, including sibling elements it did not validate.

1. Use a disposable site, synthetic contributor, test form post, and a page containing only the test shortcode. Block outbound requests and replace browser script/event/navigation sinks with counters.
2. First store one inert script element whose `src` uses an approved host but is prevented from loading. Confirm that the validator's positive branch returns the original markup.
3. Add harmless sibling markup carrying a unique `data-*` marker before and after the approved script. Do not use event handlers, external resources, forms, navigation, CSS, or executable JavaScript.
4. Record the raw stored string, DOM tree seen by the validator, selected script count/host/attributes, returned output bytes, final page DOM, and marker presence.
5. Exercise controls with zero scripts, two scripts, a non-approved host, a disallowed script attribute, sibling text only, malformed nesting, contributor versus expected manager, and the corrected build.

The safe positive is **low-role author stores container markup -> validator approves its one allowed script descendant -> renderer returns unvalidated sibling markup unchanged -> inert sibling marker appears in the shortcode DOM**. This proves policy-scope drift, not script execution. Claim stored XSS only when an independently authorized harmless browser counter demonstrates an executable sink; do not load SendPulse or any attacker-controlled host during validation.

## August 1 follow-up: test file confinement in every root-lifecycle state

[FormGent GHSA-68f5-7j6g-q5r2 / CVE-2026-3141](https://github.com/advisories/GHSA-68f5-7j6g-q5r2) adds a filesystem-validation edge that is easy to miss when a test fixture creates its upload directory too early. In versions through 1.9.2, the public `responses/attachments` route family includes a delete handler that base64-decodes a caller-supplied file token, appends it beneath the WordPress uploads path, resolves the result with `realpath()`, and compares it with `realpath()` of the intended `uploads/formgent` root. The [1.9.2 controller](https://plugins.svn.wordpress.org/formgent/tags/1.9.2/app/Http/Controllers/AttachmentController.php) builds that comparison even when the intended root does not exist. The advisory reports that this default post-install state weakens the containment check and permits traversal outside the FormGent directory. The [1.10.0 controller](https://plugins.svn.wordpress.org/formgent/tags/1.10.0/app/Http/Controllers/AttachmentController.php) instead validates a structured file token and resolves an existing upload path through a dedicated helper.

This is two independent boundaries: **may the caller invoke deletion**, and **is the resolved existing target inside the intended root for every root state**. A happy-path test performed only after the first FormGent upload may exercise a different branch from a fresh installation.

### Disposable sibling-canary matrix

1. Use a disposable WordPress site and snapshot it immediately after installing FormGent 1.9.2. Do not submit a form or upload an attachment before capturing the **root absent** fixture.
2. Create only harmless marker files in disposable directories: one beneath the intended FormGent root for the **root present** fixture and one sibling canary beneath the lab uploads directory. Do not place canaries at `wp-config.php`, plugin/theme paths, media owned by another user, logs, backups, or operating-system paths.
3. Confirm route registration, method, authentication middleware or permission callback, and normalized request parameters from source and a normal request. Record anonymous, subscriber, expected form submitter, and administrator decisions independently; route visibility alone is not proof that deletion reaches the sink.
4. Replace `wp_delete_file()` with a recorder if possible. Feed it a normal in-root token, a nonexistent target, an encoded sibling-canary traversal, repeated separators, dot segments, mixed separator forms relevant to the host, and malformed base64. The recorder should retain only the proposed canonical path and whether it is inside the expected root.
5. Run the same matrix with the FormGent root absent, present, replaced by a file, and represented through a symlink to another disposable directory. Recreate the snapshot between cases so one upload does not silently change the root lifecycle state.
6. If sink-level proof is explicitly required, permit deletion only of the disposable sibling canary, verify its pre/post hash and absence, then restore the fixture. Stop after one marker. Never delete application configuration or use a missing configuration file to trigger WordPress reinstallation.
7. Repeat on 1.10.0. Require malformed or unsigned tokens, traversal-shaped relative paths, symlink escapes, and targets outside the canonical upload root to fail before the delete sink in every lifecycle state.

The bounded positive is **anonymous delete request -> caller-selected token resolves to the disposable sibling canary while the FormGent root is absent -> delete recorder accepts that outside-root path**. An optional marker-only deletion can confirm impact in the lab, but site takeover is not necessary and must not be attempted. Report root state, token representation, canonical target, route authorization, and sink decision separately.

Generalize this check to any upload, cache, extraction, or workspace helper that calls `realpath()` on both a candidate and an intended base. Build explicit fixtures for absent, empty, populated, symlinked, moved, and permission-denied roots; reject on any failed canonicalization before comparing paths.

## August 1 follow-up: bind identity proofs to one subject and one browser flow

The August 1 WordPress wave adds several authentication failures that look different at the route level but share one durable question: **which server-held subject and initiating browser flow does this proof authorize?** Relevant records were unreviewed at scan time:

- [Single Sign On For TNG unauthenticated password reset GHSA-75h6-5h53-j8cq](https://github.com/advisories/GHSA-75h6-5h53-j8cq)
- [User Profile Builder post-registration login binding GHSA-p782-jwj4-rqqc](https://github.com/advisories/GHSA-p782-jwj4-rqqc)
- [Authora one-time-code disclosure GHSA-qh94-hqp6-76h4](https://github.com/advisories/GHSA-qh94-hqp6-76h4)
- [Login & Register Forms reset-counter binding GHSA-79h9-6m37-f387](https://github.com/advisories/GHSA-79h9-6m37-f387)
- [Chat On Desk OTP-state enforcement GHSA-ggm5-8542-75h6](https://github.com/advisories/GHSA-ggm5-8542-75h6)
- [Builderall OAuth `state` session binding GHSA-q7qm-9x83-phwf](https://github.com/advisories/GHSA-q7qm-9x83-phwf)
- [DynamicKit reset-link authority selection GHSA-wrwc-chj8-j397](https://github.com/advisories/GHSA-wrwc-chj8-j397)
- [YOP Poll forwarding-header vote-limit bypass GHSA-jqjg-6w6p-5mh7](https://github.com/advisories/GHSA-jqjg-6w6p-5mh7)

Confirm the exact plugin slug, affected version, feature configuration, route, and fixed behavior. A WordPress nonce is request provenance, not account ownership. An OTP or OAuth `state` value is useful only when the server binds it to the intended subject, purpose, initiating session, attempt budget, and expiry. A reset key can still be compromised if the requester chooses the authority placed into the emailed link.

### Two-user proof-binding matrix

1. Use a disposable site, users A and B, a local mail sink, fake mobile numbers, fake OAuth credentials, and an intercepted session-creation sink. Neither user should have administrative capabilities.
2. Record each flow as a tuple: `initiating browser`, `subject`, `purpose`, `proof`, `attempt bucket`, `redirect authority`, and `final sink`. Hash short-lived proofs in retained evidence.
3. For the TNG reset route, vary valid public nonce, email A/B, operation name, missing ownership proof, and fixed-build behavior. Intercept `reset_password()` before mutation. A public nonce must not authorize a caller-selected account reset.
4. For User Profile Builder, create user A through the affected non-default registration mode, then vary any caller-controlled identity field so the post-registration login resolver points at A, B, a nonexistent ID, and a recorder-only privileged sentinel. The newly created canonical user ID—not a request value—must select the session subject.
5. For Authora and Chat On Desk, cross A's OTP request, verification token, claimed mobile number, verification state, and reset request with B one field at a time. The issue is proven when the response exposes a usable proof or the reset/session recorder for B increments without a server-held verified state for B; do not create a live session or change a password.
6. For Login & Register Forms, keep the target fixed and vary the unauthenticated value used to key the code and attempt counter. Use a patched verifier with a tiny synthetic code space and no password mutation. Show whether changing that value resets the budget while the same target/code verification remains reachable; never brute-force a network endpoint.
7. For Builderall, start independent OAuth flows in browsers A and B against a mocked provider. Cross `state`, callback code, browser cookie, and already-connected integration state. Record only which fake token would reach the option-write recorder. Durable overwrite and first-time connection are separate cases.
8. For DynamicKit, submit only owned callback authorities and capture the local mail sink. Compare configured site origin, caller-selected origin, userinfo, explicit port, mixed case, trailing dot, encoded separators, and malformed values. Redact the reset key; the result is the authority decision, not account takeover.
9. Repeat all cases on corrected builds and require single-use proofs, one subject, one purpose, one initiating session, a server-side attempt budget, and a server-owned reset-link authority.

The bounded positives are **public request proof -> foreign-subject reset/session recorder**, **same target plus caller-resettable counter -> verification budget restarts**, **OAuth callback from browser B -> browser A's fake integration token is replaced**, or **caller URL -> valid synthetic reset key is addressed to an owned foreign authority**. Report these separately; do not collapse them into generic “authentication bypass.”

YOP Poll belongs in the same identity-provenance family but uses a network principal. Recreate direct client, approved proxy, and origin hops; test only synthetic forwarding addresses and a vote-counter recorder. A positive is **untrusted immediate peer -> caller header selects the rate-limit identity -> a second canary vote reaches the recorder**. Do not manipulate a public poll or infer that another proxy or security control is bypassed.

## August 1 follow-up: separate object ownership from business-action authority

The same wave exposes reusable role, order, ticket, and delegated-credential boundaries:

- [Pronamic Pay caller-selected user role GHSA-72h4-7f42-rjh6](https://github.com/advisories/GHSA-72h4-7f42-rjh6)
- [RealHomes Memberships unverified premium tier GHSA-mm9c-22g4-wf37](https://github.com/advisories/GHSA-mm9c-22g4-wf37)
- [Direct Payments for WooCommerce order mutation GHSA-cp6p-3j8j-57c9](https://github.com/advisories/GHSA-cp6p-3j8j-57c9)
- [Buckaroo refund authorization GHSA-63p2-7wgc-gxrq](https://github.com/advisories/GHSA-63p2-7wgc-gxrq)
- [Event Tickets order-status mutation GHSA-rpwc-gx32-cjcf](https://github.com/advisories/GHSA-rpwc-gx32-cjcf)
- [Event Tickets seating-object authorization GHSA-cfmh-2g6m-xpvm](https://github.com/advisories/GHSA-cfmh-2g6m-xpvm)
- [Fluent Support per-ticket customer reassignment GHSA-vprj-v253-jvjv](https://github.com/advisories/GHSA-vprj-v253-jvjv)
- [Pixel Tag Manager delegated conversion event GHSA-9mjw-584w-6228](https://github.com/advisories/GHSA-9mjw-584w-6228)
- [Pixelavo delegated conversion event GHSA-gm56-v4px-r8mh](https://github.com/advisories/GHSA-gm56-v4px-r8mh)

### No-op business-action harness

1. Build a two-user lab with orders A/B, tickets A/B, events A/B, one harmless custom role, and mocked payment/advertising providers. Replace refunds, fulfillment, email, role assignment, inventory writes, and external API dispatch with argument recorders.
2. For Pronamic Pay, use the ordinary Gravity Forms path and vary only the role field. Confirm form ownership and the caller's current role independently. Send a harmless role to `set_role()`; send privileged-looking slugs only to a rejecting recorder.
3. For RealHomes and Direct Payments, cross user A's request with order/membership objects owned by A and B. Vary status, tier, payment label, and proof-file metadata independently. Persist only marker states and restore them immediately.
4. For Buckaroo and Event Tickets, compare anonymous, subscriber, contributor, scoped event manager, and expected operator. A valid nonce does not replace a refund/order capability check; event-level edit access does not authorize every seating layout or attendee assignment.
5. For Fluent Support, create agents scoped to separate synthetic inboxes. Cross ticket ID, current customer, replacement customer, inbox, and agent one field at a time. Stop at a no-op reassignment recorder; never read ticket bodies.
6. For Pixel Tag Manager and Pixelavo, block outbound networking and substitute a local conversion-API recorder loaded with a fake token. Compare missing, public-page, stale, wrong-action, and expected nonces plus malformed event fields. Record whether an anonymous caller can spend the site's delegated API authority, not whether the provider accepted an event.
7. Repeat on fixed builds and require capability, object ownership, parent-child scope, writable-field allowlists, server-side payment state, and idempotency before any sink.

The safe result is a decision table showing **caller -> proof -> canonical object -> required capability -> recorder action**. A JSON success, guessed object ID, or public nonce alone is not enough. Do not issue refunds, alter real orders, grant premium service, reassign customer records, modify event inventory, or send advertising events.

## August 1 follow-up: prove chained filesystem selectors without touching host files

Two records add useful multi-stage filesystem checks:

- [Nex Forms stored-location to deletion chain GHSA-2446-gfm3-96v2](https://github.com/advisories/GHSA-2446-gfm3-96v2)
- [Support Genix ticket-attachment traversal GHSA-g8p2-p6hq-8pw4](https://github.com/advisories/GHSA-g8p2-p6hq-8pw4)

Nex Forms reportedly lets the same authenticated principal first store a caller-selected `location` value and later send the resulting record through a deletion handler that passes the stored path to `unlink()`. Support Genix reportedly applies an extension allowlist to an attachment-download selector without first proving that the canonical file belongs to the selected ticket and attachment root. HTML sanitization does not make a string safe as a path, and an extension allowlist does not provide confinement.

1. Use disposable directories containing only an in-root attachment and a sibling text canary. Patch `unlink()` and file-open/read helpers to record canonical paths without deleting or returning content.
2. For Nex Forms, capture write principal, stored raw bytes, canonicalized stored value, deletion trigger principal, and final sink argument separately. Test own record, foreign record, nonexistent record, relative sibling path, absolute sibling path, mixed separators, and symlinked canaries.
3. For Support Genix, compare valid own-ticket attachment ID, foreign-ticket attachment ID, sibling canary with an allowed extension, disallowed extension, encoded separators, duplicate path parameters, and fixed-build behavior. Stop when the recorder receives an outside-root path.
4. Require corrected builds to resolve an attachment by a server-side object ID, bind it to the selected ticket and caller, canonicalize an existing target, verify root containment, reject symlink escape, and only then open or delete it.

The bounded positives are **authorized first-stage record write -> stored synthetic path -> later delete recorder receives sibling canary** and **download route -> extension-approved but outside-root sibling path reaches read recorder**. Do not delete a file, return canary content, inspect another user's ticket, or use configuration, credential, log, backup, plugin, or operating-system paths.

## August 2 follow-up: verify token cryptography before identity lookup

[WooCommerce Social Login GHSA-qwc9-q2f8-q72q](https://github.com/advisories/GHSA-qwc9-q2f8-q72q) reports that versions through 2.8.7 decode an Apple `id_token` payload but do not verify its signature against Apple's keys or validate issuer, audience, or expiry before using the email claim to select a WordPress user. The same record says the route nonce is localized into the public login page. The durable chain is therefore **public request proof -> unverified token claims -> email-to-account lookup -> session sink**. A public nonce is expected CSRF/request-provenance material; it cannot replace cryptographic token verification or account binding.

The record was unreviewed and did not link public plugin source at scan time. Treat the route and affected-version details as a lead until reproduced against the exact commercial package. Do not infer behavior from a similarly named plugin.

### Synthetic Apple-token decision matrix

1. Use a disposable WordPress site, the exact affected package, users A and B with no administrative capabilities, fake Apple client settings, blocked outbound networking, and an intercepted `wp_set_auth_cookie()` or equivalent session sink.
2. Fetch the normal logged-out login page and record whether it publishes the route nonce. Hash the nonce in retained evidence; do not call its public availability a disclosure by itself.
3. Build only synthetic JWT-shaped fixtures. Keep B's fake lab email in the payload and vary valid structure, invalid signature, unknown key ID, wrong issuer, wrong audience, expired `exp`, future `iat`, missing email, duplicate claim keys, and malformed base64 one property at a time. Do not use a real Apple identity or signing key.
4. Patch the session sink to record the resolved canary user ID and return without setting a cookie. Record token parsing, key selection, signature decision, claim validation, email normalization, account lookup, and sink reachability independently.
5. Include random/missing nonce, expected public nonce, unknown email, A/B email crossover, existing linked account, and fixed-build controls. A corrected flow must reject before identity lookup when signature or required claims fail and must bind the token's audience to the configured Apple client.

The bounded positive is **logged-out visitor obtains ordinary route nonce -> invalid-signature synthetic token naming B -> B reaches the no-op session recorder without signature/issuer/audience/expiry acceptance evidence**. Do not mint an administrator token, set a live cookie, reuse a real Apple token, or retain a login proof.

## August 2 follow-up: bind authorization and file selection to one attachment

[User Access Manager GHSA-mxw9-rxrv-85f3](https://github.com/advisories/GHSA-mxw9-rxrv-85f3) reports a selector mismatch through 2.3.15: a caller supplies the file representation through `uamgetfile`, while a valid public `attachment_id` can leave a global post available for the access decision when URL-to-attachment resolution returns zero. The [2.3.14 redirect controller](https://plugins.svn.wordpress.org/user-access-manager/tags/2.3.14/src/Controller/Frontend/RedirectController.php) confirms the relevant shape: it converts the supplied URL into a filesystem path, resolves an attachment ID through `attachment_url_to_postid()`, checks access on the resulting `FileObject`, and then sends that object's path to the file handler. The [file handler](https://plugins.svn.wordpress.org/user-access-manager/tags/2.3.14/src/File/FileHandler.php) eventually opens an existing path for delivery.

The reusable question is whether **the object that passed authorization is the same canonical object whose bytes reach the read sink**. Never test this by requesting `wp-config.php`, credentials, backups, logs, another tenant's media, or operating-system files.

### Two-selector read-recorder workflow

1. Build a disposable site with public attachment A, restricted attachment B, and a sibling plain-text canary outside the approved upload root. Patch `fopen()`, range delivery, and accelerator-header helpers to record the proposed canonical path and return no content.
2. Capture a normal protected-download request. Vary `attachment_id`, `uamfiletype`, and `uamgetfile` independently: A/A, B/B, A/B, B/A, nonexistent object, traversal-shaped sibling canary, absolute canary path, encoded separators, duplicate parameters, and symlink aliases.
3. For every case record the raw selectors, `attachment_url_to_postid()` result, global/current post ID, `FileObject` ID and type, access decision, constructed path, canonical path, and final recorder call. Reset global query state between requests so fixture leakage is visible rather than accidental.
4. Repeat without `attachment_id`, with an invalid ID, with a private current post, and after a clean WordPress bootstrap. This determines whether the claimed fallback genuinely depends on request-populated global state.
5. Repeat on the corrected changeset/build. Require a failed URL lookup to reject, one server-resolved attachment ID to drive both access and path selection, canonical upload-root confinement, and symlink-safe open behavior.

The bounded positive is **public attachment A authorizes -> caller-selected sibling canary remains the read target -> recorder receives the outside-root path while the authorized object ID is still A**. A mismatched response, path-construction observation, or source-only fallback is insufficient without sink reachability. Stop before opening or returning the canary.

## August 2 follow-up: distinguish a public nonce from SVG file authority

[CubeWP Framework GHSA-2cff-wc4f-2m48](https://github.com/advisories/GHSA-2cff-wc4f-2m48) reports unauthenticated path traversal through 1.1.30 when a posts shortcode or widget with AJAX loading publishes the required nonce. The [1.1.30 `cubewp_get_svg_content()` source](https://plugins.svn.wordpress.org/cubewp-framework/tags/1.1.30/cube/functions/admin-functions.php) confirms a file-authority sink: it accepts an icon structure, can translate a URL beginning with the site/home URL into an `ABSPATH` path, and calls `file_get_contents()` when that path exists. The advisory establishes the claimed public route; source confirms the helper sink. Reproduce the request-to-helper edge before reporting the full chain.

### Patched SVG-read harness

1. Use a fresh CubeWP 1.1.30 lab with one public AJAX-loaded posts widget, an in-root inert SVG marker, and a sibling text canary containing SVG-like plain text. Block outbound networking and patch `file_get_contents()` plus `wp_safe_remote_get()` to argument recorders.
2. Fetch the widget anonymously and record nonce provenance, action name, icon structure, and route registration. Compare missing, random, expired, public-page, subscriber, and administrator nonce values; nonce acceptance is not file authorization.
3. Submit only canary selectors: registered attachment ID, expected local SVG URL, dot-segment sibling URL, encoded separators, URL with userinfo/port, duplicate URL fields, symlinked in-root path, symlink to the sibling canary, nonexistent path, and an owned remote callback URL handled only by the recorder.
4. Record raw URL, prefix check, URL-to-path replacement, normalized/canonical path, selected branch, and recorder argument. Do not let the helper read or render the sibling file and do not contact an internal service.
5. Repeat on the corrected changeset/build. Require a server-resolved media attachment, verified SVG type/content policy, canonical containment beneath the approved media root, symlink rejection, and an explicit outbound-fetch policy before either sink.

The bounded positive is **anonymous widget yields ordinary nonce -> caller-selected local URL survives into `cubewp_get_svg_content()` -> patched reader receives the sibling canary outside the approved media root**. This proves file-selector authority drift, not disclosure of a real secret. Treat the remote-fetch fallback as a separate SSRF surface and claim it only when an owned callback records a request after final-destination policy checks.

## August 2 follow-up: bind every proof, selector, and delegated capability to one object

The next unreviewed WordPress wave adds eighteen reusable checks. They belong here because each composes an apparently valid proof or low-role capability with a second selector the server fails to bind:

- appointment bulk scope and unauthenticated deletion: [GHSA-j5pv-734r-xv95 / CVE-2026-16540](https://github.com/advisories/GHSA-j5pv-734r-xv95);
- file-metadata update to download selection: [GHSA-2rf9-6fhx-g6mg / CVE-2026-16292](https://github.com/advisories/GHSA-2rf9-6fhx-g6mg);
- unauthenticated media-ID download: [GHSA-953r-r7wf-54g9 / CVE-2026-16285](https://github.com/advisories/GHSA-953r-r7wf-54g9);
- foreign notification and attachment deletion: [GHSA-77fq-7qxg-43vp / CVE-2026-16291](https://github.com/advisories/GHSA-77fq-7qxg-43vp) and [GHSA-vpwf-36p2-3fwr / CVE-2026-15248](https://github.com/advisories/GHSA-vpwf-36p2-3fwr);
- public account create/update with a caller role: [GHSA-vrg4-ffx9-cfhg / CVE-2026-16256](https://github.com/advisories/GHSA-vrg4-ffx9-cfhg);
- reset and social-login identity binding: [GHSA-5hm3-fq9v-vwj3 / CVE-2026-16261](https://github.com/advisories/GHSA-5hm3-fq9v-vwj3) and [GHSA-rhj3-v77h-x35q / CVE-2026-12586](https://github.com/advisories/GHSA-rhj3-v77h-x35q);
- event quick-edit object authorization and delayed object deserialization: [GHSA-5hqh-mj83-f2f6 / CVE-2026-16064](https://github.com/advisories/GHSA-5hqh-mj83-f2f6) and [GHSA-xh9j-gpmv-5c2v / CVE-2026-16062](https://github.com/advisories/GHSA-xh9j-gpmv-5c2v);
- low-role navigation configuration crossing into public rendering: [GHSA-9jvp-fc5f-j7qr / CVE-2026-15385](https://github.com/advisories/GHSA-9jvp-fc5f-j7qr) and [GHSA-m349-rc55-q5w8 / CVE-2026-11872](https://github.com/advisories/GHSA-m349-rc55-q5w8);
- frontend versus REST content-policy drift: [GHSA-4v4h-6mhp-rwxf / CVE-2026-15939](https://github.com/advisories/GHSA-4v4h-6mhp-rwxf);
- public use or disclosure of stored API authority: [GHSA-xqfh-qj3w-mr75 / CVE-2026-15241](https://github.com/advisories/GHSA-xqfh-qj3w-mr75) and [GHSA-465m-pvh5-8rh9 / CVE-2026-15236](https://github.com/advisories/GHSA-465m-pvh5-8rh9);
- OTP verification detached from the selected phone/account: [GHSA-63jw-46hv-gwp2 / CVE-2026-15206](https://github.com/advisories/GHSA-63jw-46hv-gwp2);
- board import detached from source-board authorization: [GHSA-66hj-2rxc-44vr / CVE-2026-14938](https://github.com/advisories/GHSA-66hj-2rxc-44vr); and
- unauthenticated REST mutation of consent, post, and license state: [GHSA-xw6w-vrqp-fhq4 / CVE-2026-13389](https://github.com/advisories/GHSA-xw6w-vrqp-fhq4).

Confirm the exact plugin or theme slug, edition, feature configuration, affected version, route, and corrected behavior. Several descriptions combine multiple outcomes; prove each route-to-sink edge separately rather than inheriting the record's maximum impact.

### Two-object authorization matrix

Build synthetic objects A and B under different owners: appointments, uploads, notifications, media attachments, posts, events, menus, and boards. Give a low-role user legitimate access only to A. Replace read, delete, publish, import, and metadata-write sinks with recorders where possible.

| Operation | Control selector | Crossover selector | Bounded evidence |
| --- | --- | --- | --- |
| bulk appointment read/delete | A-only filter or current requester | omitted filter, B ID, all-records flag | recorder lists B's canary ID or receives B delete, no personal data |
| file metadata/update/download | A upload and its metadata | B upload ID/path with A or public proof | B canonical ID reaches a no-content read recorder |
| notification/media delete | A object ID | B object ID | no-op delete recorder receives B after low-role authorization |
| event quick edit | editable event A | post/page B plus title/status marker | B write recorder receives a reversible marker |
| board import | authorized board A | stages/tasks from B | import recorder receives B's synthetic item IDs |
| REST restriction | front-end-denied post B | alternate REST representation of B | response recorder selects B's marker content |

Exercise anonymous, owner, low-role non-owner, expected manager, nonexistent object, wrong parent, duplicate parameter, stale nonce, and corrected-build controls. Record the canonical object used at the authorization guard and the canonical object reaching the sink. Stop at IDs, hashes, and marker fields; never return appointment personal data, private uploads, board descriptions, or attachment bytes, and never perform a destructive delete.

The decisive positive is **proof valid for caller or object A -> caller-selected object B -> B reaches a read/write/delete/import recorder without a B-specific capability and ownership decision**. A successful HTTP status, enumerable numeric ID, or route visibility alone is insufficient.

### Account creation, password reset, social login, and OTP subject matrix

Use disposable non-administrator users A and B, fake phones, invalid-signature third-party identity fixtures, a local mail sink, and patched account/session/password/role sinks.

1. For POUCO Import Users, test each public AJAX action independently. Record whether authentication, nonce, account-create/update capability, target-user binding, and a role allowlist execute before the sink. Send only a harmless custom role to the recorder; do not create an administrator.
2. For login-social, separate password reset from third-party sign-in. Cross requester, target user, reset key, provider subject, verified-signature decision, claimed email, and final session subject one field at a time. Invalid-signature or absent-proof fixtures must fail before account lookup.
3. For Lenxel WP, compare public CSRF nonce acceptance with reset-key and target-ownership decisions. A nonce can establish request provenance; it cannot authorize a caller-selected account.
4. For SMS Alert, verify A's fake phone and OTP, then switch only the later login/signup phone selector to B. Intercept session creation. The server must bind the verified phone, verification attempt, browser session, target account, purpose, and expiry as one tuple.
5. Repeat on corrected builds, expire every proof, and invalidate all canary sessions.

Safe positives are **public account route -> caller-selected harmless role reaches a no-op role sink**, **unverified reset/provider proof -> foreign-user password or session recorder**, or **OTP for phone A -> phone B selects the session subject**. Do not change passwords, send messages, mint live sessions, or use real provider identities.

### Delegated API and credential authority

AI ChatBot for WooCommerce and Gallery for Google Photos illustrate two sides of stored third-party authority: a public route may **use** the operator's credential, or it may **return** persistent OAuth material. Use fake provider credentials and mocked transports only.

1. For the chatbot, load a fake API token into a disposable site, disconnect outbound networking, and replace the provider client with a recorder. Compare anonymous, authenticated, nonce, feature-disabled, knowledge-base-disabled, and fixed-build cases. Send one inert prompt marker and return no indexed content.
2. For the gallery, seed only fake access/refresh tokens. Inventory public route families and intercept response serialization. A positive is the unauthenticated serializer selecting synthetic credential fields; do not retain or replay any real token.
3. Record separately: route authentication, nonce provenance, requested operation, canonical credential owner, provider scope, outbound argument, response fields, and billing/content sink.

Report **unauthenticated delegated API dispatch** separately from **credential disclosure** and **knowledge-base selection**. Provider acceptance, cost, linked-account compromise, and private-content access remain unproven unless separately authorized—and are unnecessary for this workflow.

### Delayed deserialization and menu rendering

Event Booking Manager's object-injection record explicitly says the affected plugin does not supply its own POP chain. Prove only the storage-to-deserializer boundary: store an inert serialized marker through a contributor-reachable event field, patch `unserialize()` or object construction to record the class name and input hash, and trigger the normal later read. Do not load a gadget, invoke magic methods, delete files, read data, or claim code execution.

For RT Mega Menu and Clever Mega Menu, distinguish configuration authorization from browser execution. Use a subscriber canary, synthetic menu item, and harmless CSS/attribute-shaped markers. Record nonce provenance, capability decision, menu-item ownership, persisted setting, render context, and detached DOM/AST result. Do not use event handlers or script payloads. A useful result is **subscriber -> menu configuration sink -> inert marker escapes its intended attribute/style node in a detached parser**; site takeover requires a separate, authorized executable-sink proof.

The adjacent generic stored/reflected XSS records, cache-flush availability issue, low-impact settings reset, and empty advisory summary were processed without publication because they add no distinct workflow beyond the existing render, role, and business-action matrices.

## August 3 follow-up: cross-check object, identity, upload, and role selectors

The next WordPress wave adds four reusable boundary families. The GitHub records were unreviewed when processed; confirm plugin slug, affected version, route registration, prerequisite role, and corrected behavior before reporting.

### Parent, owner, and publication-state authorization

- Dokan vendor product-attribute writes and bulk order-status changes: [GHSA-cjjh-8xvm-fchv / CVE-2026-16565](https://github.com/advisories/GHSA-cjjh-8xvm-fchv) and [GHSA-rgp2-2vg6-97f5 / CVE-2026-16564](https://github.com/advisories/GHSA-rgp2-2vg6-97f5);
- Academy LMS lesson enrollment and publication state: [GHSA-9988-37r6-j7j6 / CVE-2026-16563](https://github.com/advisories/GHSA-9988-37r6-j7j6);
- Classified Listing cross-owner post content and revenue totals: [GHSA-xw94-m5qr-wj9w / CVE-2026-16274](https://github.com/advisories/GHSA-xw94-m5qr-wj9w) and [GHSA-jxrw-x44m-c9mq / CVE-2026-16276](https://github.com/advisories/GHSA-jxrw-x44m-c9mq);
- Contest Gallery foreign-post deletion: [GHSA-pwq7-3xxm-qxqg / CVE-2026-16057](https://github.com/advisories/GHSA-pwq7-3xxm-qxqg);
- Tag, Category, and Taxonomy Manager private/draft post derivation: [GHSA-2fw4-4h2j-gcmv / CVE-2026-15231](https://github.com/advisories/GHSA-2fw4-4h2j-gcmv); and
- GEO my WP foreign geolocation modification/deletion: [GHSA-qgxr-8r3m-cw55 / CVE-2026-15260](https://github.com/advisories/GHSA-qgxr-8r3m-cw55).

Use two vendors/authors/students, parent objects A and B, and synthetic child objects. Give the low-role principal legitimate access only to A. Cross only one selector per request: product, order, lesson, course enrollment, publication state, post, report scope, or geolocation record. Replace update, status-change, and delete sinks with no-op recorders; return only marker text for read tests. The positive is **A-authorized principal or parent -> B selector -> B's marker reaches the read/write/delete recorder without B ownership, enrollment, publication, or capability authorization**. Never return paid lesson content, revenue, private posts, customer orders, or location data.

### Account subject and canonical role enforcement

- ChamaWP arbitrary-user reset and unauthenticated object input: [GHSA-6m7v-g5wq-gghp / CVE-2026-16300](https://github.com/advisories/GHSA-6m7v-g5wq-gghp) and [GHSA-w2rh-rmh8-jmwq / CVE-2025-15672](https://github.com/advisories/GHSA-w2rh-rmh8-jmwq);
- Import and export users and customers role/edit-policy bypass: [GHSA-xw98-5fp3-v7vg / CVE-2026-16534](https://github.com/advisories/GHSA-xw98-5fp3-v7vg);
- Simple Membership failed-user-creation identity confusion: [GHSA-7g75-5pmj-3v8p / CVE-2026-15930](https://github.com/advisories/GHSA-7g75-5pmj-3v8p); and
- SoftMarket email-verification session binding: [GHSA-6gxj-34hr-jj8j / CVE-2026-14557](https://github.com/advisories/GHSA-6gxj-34hr-jj8j).

Build users A and B with harmless custom roles and intercept password, email, role, and session sinks. Cross requester, reset/verification proof, claimed user ID, returned user-creation result, CSV row, canonical editable user, submitted role, and final session subject one field at a time. Force user creation to return each relevant `WP_Error`, falsey, zero-like, and valid canary representation. For ChamaWP deserialization, use a patched `unserialize()` recorder with an inert class-name marker only—no gadget or magic method.

Safe positives are **proof for A -> B reaches a password/session recorder**, **failed create result -> existing canary user reaches the update recorder**, or **`create_users`-only principal -> disallowed canary role/foreign-user edit reaches the role or account recorder**. Do not reset a password, change an email, assign `administrator`, set a cookie, or instantiate an object.

### Upload container, extension, and public-handler drift

- Articulate Content archive validation to a server-executable public file: [GHSA-v4q5-7cp7-m46j / CVE-2026-16060](https://github.com/advisories/GHSA-v4q5-7cp7-m46j);
- Personal QR Message and Webinfos unauthenticated file handlers: [GHSA-r4mq-7p9v-x8fv / CVE-2026-16250](https://github.com/advisories/GHSA-r4mq-7p9v-x8fv) and [GHSA-jm79-ggg6-34q9 / CVE-2026-12872](https://github.com/advisories/GHSA-jm79-ggg6-34q9); and
- SVG Support `.svgz` sanitizer drift: [GHSA-2v5f-qf73-676h / CVE-2026-13340](https://github.com/advisories/GHSA-2v5f-qf73-676h).

Use a patched write recorder and inert files only. For archive tests, include one allowed media marker plus one dangerous-looking filename containing plain text; never include PHP or executable syntax. For direct handlers, vary authentication, nonce, capability, extension, MIME, case, duplicate suffix, and destination independently. For `.svgz`, gzip the same harmless SVG marker used by the `.svg` control and compare decompression, sanitizer invocation, stored bytes, response type, and detached DOM. A positive requires the disallowed representation to reach the public-path write recorder or to bypass the sanitizer that the equivalent `.svg` invokes. File placement is not execution, and a served SVG-like file is not XSS without an independently proven browser sink.

### Query grammar items from the same wave

LogMyTrip cookie-to-query ([GHSA-q8gv-w79g-jw6j / CVE-2026-16572](https://github.com/advisories/GHSA-q8gv-w79g-jw6j)), Link Library unauthenticated query input ([GHSA-pm7r-7m99-28qp / CVE-2026-16532](https://github.com/advisories/GHSA-pm7r-7m99-28qp)), and Super Store Finder unauthenticated AJAX input ([GHSA-hr2r-68v6-qv47 / CVE-2026-12965](https://github.com/advisories/GHSA-hr2r-68v6-qv47)) fit the existing query-recorder method: send delimiter-shaped inert values, intercept the final SQL, and compare parser tokens with bound-parameter controls. Do not execute extraction, timing, stacked-statement, or destructive payloads.

The adjacent generic stored-XSS, low-impact group-membership metadata, administrator-only object injection, and brute-force/timing records were processed without separate publication because they do not add a distinct operator workflow beyond the existing render, object, deserialization, and authentication matrices.

## August 7 follow-up: bind plugin routes to server-owned identity, object, payment, and integration authority

An August 7 unreviewed WordPress wave adds reusable checks for public integration replacement, transaction arithmetic, login-flow binding, object ownership, local-file selection, REST route-family drift, token cryptography, payment completion, and password-reset subject proof:

- Ajax Search Lite unauthenticated deserialization: [GHSA-m7vw-4232-p79x / CVE-2026-16258](https://github.com/advisories/GHSA-m7vw-4232-p79x);
- Templately cloud-connection replacement: [GHSA-4vxc-ggfm-6c86 / CVE-2026-15359](https://github.com/advisories/GHSA-4vxc-ggfm-6c86);
- WP Events Manager quantity/price authority: [GHSA-xm6j-g6w8-55mf / CVE-2026-14205](https://github.com/advisories/GHSA-xm6j-g6w8-55mf);
- Estatik social-login flow binding: [GHSA-jqr2-6x6h-fvmp / CVE-2026-16262](https://github.com/advisories/GHSA-jqr2-6x6h-fvmp);
- Subscriptions for WooCommerce object ownership: [GHSA-qhjm-7mgh-6mhm / CVE-2026-15214](https://github.com/advisories/GHSA-qhjm-7mgh-6mhm);
- WP Maps low-role local-file selection: [GHSA-v8wm-6qmw-j72p / CVE-2026-16263](https://github.com/advisories/GHSA-v8wm-6qmw-j72p);
- Content Views low-role query construction: [GHSA-gp8v-vc4r-wpf4 / CVE-2026-15361](https://github.com/advisories/GHSA-gp8v-vc4r-wpf4);
- Password Protected REST route-family regression: [GHSA-qmm8-q2c2-c4m3 / CVE-2026-14943](https://github.com/advisories/GHSA-qmm8-q2c2-c4m3);
- MStore API vendor-order scope, review creation, phone-token verification, and payment completion: [GHSA-wgmj-93jg-87w3 / CVE-2026-16039](https://github.com/advisories/GHSA-wgmj-93jg-87w3), [GHSA-9px3-jf5v-3473 / CVE-2026-16041](https://github.com/advisories/GHSA-9px3-jf5v-3473), [GHSA-w2g6-85hw-mgcv / CVE-2026-16030](https://github.com/advisories/GHSA-w2g6-85hw-mgcv), and [GHSA-5xp8-jj53-535m / CVE-2026-16038](https://github.com/advisories/GHSA-5xp8-jj53-535m);
- TrueBooker password-reset authorization: [GHSA-9p7q-wqgp-8mm8 / CVE-2026-14365](https://github.com/advisories/GHSA-9p7q-wqgp-8mm8) and [GHSA-g634-mqw6-9p22 / CVE-2026-14364](https://github.com/advisories/GHSA-g634-mqw6-9p22); and
- SAML Single Sign On algorithm/key confusion: [GHSA-p847-q8vx-c3fg / CVE-2026-15013](https://github.com/advisories/GHSA-p847-q8vx-c3fg).

Confirm the exact plugin slug, edition, affected version, enabled feature, route/action, and corrected behavior. These were unreviewed records at scan time. Use a disposable site, synthetic non-administrator users and objects, fake integration/token material, mocked gateways and IdPs, patched file/query/deserialization/session/password sinks, and no-op mutations. Never replace a production integration, retrieve customer orders or subscriptions, include a host PHP file, execute a POP chain, create a paid order, change a password, or mint a live session.

### Treat integration replacement as a supply-chain edge

For Templately, seed the plugin with a fake cloud connection and intercept option/configuration persistence. Compare anonymous, subscriber, expected administrator, missing proof, random proof, feature-disabled, and fixed-build requests. Record the authenticated principal, handler, capability and nonce decisions, old integration identity, submitted identity, and no-op write sink.

After the fake replacement, use a mocked template service to determine whether template listing/import resolves through the new account. Return only an inert template ID; do not import markup or files. A bounded positive is **anonymous handler -> no authorization decision -> fake cloud identity reaches persistent connection recorder -> later template resolver selects the owned mock account**. Report connection replacement separately from attacker-controlled template ingestion or execution.

### Reconstruct every commerce tuple on the server

Use synthetic products, events, bookings, orders, subscriptions, reviews, and customers. Patch fulfillment, review publication, order-state, and payment-provider calls.

| Surface | Attacker-selected field | Server-owned binding | Safe sink |
| --- | --- | --- | --- |
| WP Events Manager | quantity | event, unit price, allowed range, computed total, booking owner | arithmetic and booking-state recorder |
| Subscriptions for WooCommerce | subscription ID | current customer owns canonical subscription | marker-only serializer |
| MStore vendor orders | order/filter selector | vendor/customer scope on the final query | query/serializer returning canary IDs only |
| MStore reviews | product, reviewer identity, rating | authenticated customer and verified purchase | no-op review-create recorder |
| MStore payment completion | order ID and success/status claim | provider transaction, merchant, amount, currency, order, lifecycle | no-op paid-state recorder |

Test omitted, zero, negative, fractional, duplicate, oversized, and expected quantities without creating a booking. For object scope, cross A's authenticated customer/vendor context with A and B marker objects. For payment completion, use a local provider stub and send missing, malformed, synthetic-success, wrong-order, replayed, stale, and already-completed responses. A useful result requires a canonical foreign object or state transition to reach the recorder; a `200`, guessed ID, accepted parameter, or computed zero alone is insufficient.

### Bind browser login, token verification, and password reset to one subject

Use browser sessions A/B, canary users A/B, a mocked OAuth/SAML provider, invalid-signature synthetic tokens/assertions, and patched session/password sinks.

1. For Estatik, initiate social login independently in A and B. Cross callback code, `state`, browser cookie, provider subject, and local-account selector one field at a time. The final local session must remain bound to the browser that initiated that exact provider flow. A positive is **attacker-started flow -> victim callback/browser -> no-op session sink selects the attacker's canary account**; do not submit victim data after login.
2. For MStore phone login, vary malformed structure, invalid signature, unknown key, wrong algorithm, wrong subject/phone, expiry, replay, and a valid synthetic control. Require cryptographic acceptance before phone-to-account lookup. Knowing a lab phone number is only a precondition, not authentication proof.
3. For TrueBooker, cross requester, target user ID/email, reset nonce/key, purpose, expiry, and browser session. A public route or request nonce must not authorize a caller-selected subject. Stop when a no-op password recorder receives B under proof not issued for B.
4. For SAML Single Sign On, generate an isolated RSA test key and synthetic assertions only. Compare the configured RSA signature method with an attacker-declared HMAC method while patching session creation. Record configured algorithm/key type, declared `SignatureMethod`, key-cast path, verification result, issuer/audience/recipient/time decisions, resolved canary subject, and final no-op sink. A bounded positive is **attacker-declared algorithm -> RSA public bytes are reused as HMAC key material -> forged synthetic assertion reaches B's session recorder**. Never use a production IdP certificate or target an administrator.

Keep login CSRF, invalid-signature token acceptance, reset-subject drift, and signature algorithm confusion as four separate findings. An assertion parser accepting input is not authentication bypass unless the invalid proof reaches the final synthetic identity sink.

### Compare canonical routes, alternate REST routes, and final sinks

The Password Protected record describes a regression after a previous fix: a configuration can protect normal page routes while REST representations remain public. Seed one ordinary public post and one password-gated marker post, then enumerate detail, collection, search, embed, revisions, author/account, and alternate-version REST routes. Record the enabled option, route match, authentication/permission callback, canonical object, fields selected, and final serialized marker. A positive requires the protected synthetic marker through the alternate route; route discovery or an account-ID field alone does not establish protected-content access.

Apply the same final-sink discipline to WP Maps and Content Views:

- **WP Maps:** seed only an in-root inert PHP fixture whose include body increments a recorder and a sibling plain-text canary. Test subscriber versus expected manager, raw/encoded separators, absolute paths, stream-wrapper-shaped values rejected by the recorder, symlinks, nonexistent files, and fixed builds. Stop at canonical include-path selection; do not include WordPress, plugin, configuration, credential, or host files and do not execute PHP.
- **Content Views:** send delimiter-shaped inert values to the affected AJAX parameter and intercept the final SQL before execution. Preserve raw input, sanitizer/escaping output, constructed query, parser tokens, parameter bindings, principal, and fixed-build diff. Never send extraction, timing, stacked-statement, file, or destructive payloads.

### Prove deserialization separately from gadget availability

For Ajax Search Lite, identify the exact unauthenticated request field and instrument `unserialize()` plus object construction. Submit an inert serialized fixture naming a harmless test class that has no magic methods. Capture route reachability, raw-input hash, allowed-class policy, selected class, and recorder event. Inventory installed plugin/theme classes and autoloaders offline, but do not instantiate a POP gadget or claim code execution merely because untrusted bytes reach deserialization. The bounded result is **anonymous request -> attacker-shaped serialized marker -> patched deserializer/object-class recorder**; gadget presence and executable impact remain separate, unproven edges.

Question2Answer persistent-cookie invalidation and the adjacent reflected/stored XSS, vague local-service permission, firmware hash, and availability-only records were source-tracked without a separate workflow. Password-reset session revocation is already covered by the wiki's subject/session matrices; the remaining records did not add a more specific safe sink than existing renderer, query, and local-permission guidance.

## August 7 payment-proof and CAPTCHA-cache follow-up

Three newly published unreviewed records extend the same server-owned tuple methodology:

- [WP Events Manager GHSA-6g36-5qr8-2jpf / CVE-2026-15148](https://github.com/advisories/GHSA-6g36-5qr8-2jpf) reports that versions before 2.2.5 accept incoming payment notifications without proving the configured merchant account or matching the paid amount to the booking total, including when the selected booking belongs to another user;
- [Subscriptions for WooCommerce GHSA-p384-7c3j-gqm7 / CVE-2026-15211](https://github.com/advisories/GHSA-p384-7c3j-gqm7) reports that versions before 2.0.1 capture a caller-supplied PayPal order token and accept `COMPLETED` without binding that token or captured amount to the local order; and
- [Simple CAPTCHA with Cloudflare Turnstile GHSA-w6f5-3mw7-jjxq / CVE-2026-15239](https://github.com/advisories/GHSA-w6f5-3mw7-jjxq) reports that versions before 1.42.0 key Forminator's short-lived validation cache with a reusable caller-controlled request value rather than the single-use Turnstile challenge token.

Confirm exact plugin slug, affected version, enabled gateway/Forminator integration, route, provider response fields, cache key derivation, and fixed behavior. Do not contact a live payment or CAPTCHA provider.

### Cross payment proof, merchant, amount, and object independently

Use two synthetic users, bookings/orders A and B with different totals, fake merchant identities M1/M2, and a local provider adapter. Patch capture, paid-state, fulfillment, ticket, email, and webhook sinks.

| Input | Local object | Expected secure result |
| --- | --- | --- |
| proof for A, M1, exact amount A | A | one idempotent marker transition |
| proof for A | B | reject before B state sink |
| proof for M2 | A under configured M1 | reject merchant mismatch |
| completed proof for lower amount | A | reject amount/currency mismatch |
| already-consumed proof for A | A or B | acknowledge safely; no second transition |

For WP Events Manager, vary booking ID, owner, configured merchant/receiver identity, provider transaction, amount, currency, status, and replay state one field at a time. For Subscriptions for WooCommerce, seed an approved but uncaptured fake provider order, then cross the caller-supplied token with local orders A/B and vary captured amount, currency, merchant, capture status, and token reuse. Record the tuple returned by the local adapter and the canonical local tuple immediately before the no-op paid-state sink.

The bounded positives are **synthetic notification valid in isolation -> foreign booking B or wrong merchant/amount reaches B's paid-state recorder** and **caller-supplied provider token -> fake capture returns `COMPLETED` -> mismatched local order or total reaches the paid-state recorder**. Do not create goods, bookings, tickets, subscriptions, capture funds, or submit provider-approved tokens from a real account.

### Treat CAPTCHA caches as consumed-proof state

Replace Turnstile verification with a deterministic local verifier and Forminator submission with a no-op action recorder. Issue challenge tokens T1/T2 and caller-controlled request/cache values K1/K2.

1. Submit T1 with K1 once and confirm the synthetic verifier accepts it.
2. Replay K1 with the challenge token omitted, random, expired, already consumed, or replaced by T2. A cache hit must not substitute for a valid single-use proof bound to the same form, action, browser/session where intended, and submission attempt.
3. Cross K1 between two disposable forms and two browser sessions. Vary duplicate parameters, case/encoding normalization, expiry boundaries, and parallel requests under a deterministic barrier.
4. Record the raw challenge hash, caller cache value hash, derived cache key, hit/miss, form/action identity, consumed state, verifier invocation, and final no-op submission decision.
5. Repeat on 1.42.0 or another corrected build. Require replayed or token-less attempts to fail before the Forminator action sink.

A safe positive is **one accepted synthetic challenge under K1 -> later token-less or invalid-token request reuses K1 -> validation cache returns success -> no-op form action increments**. This proves anti-abuse proof replay; it does not prove account creation, spam delivery, rate-limit bypass outside this integration, or compromise of Cloudflare Turnstile. Use only disposable forms and never automate submissions against a public site.

## August 7 commerce-proof, shortcode, and protected-content follow-up

A late unreviewed wave expands three existing matrices.

### Re-derive the complete commerce tuple

Sources: Easy Booking minimum duration [GHSA-c9jf-h8vc-955p / CVE-2026-14831](https://github.com/advisories/GHSA-c9jf-h8vc-955p), PhonePe transaction-to-order binding [GHSA-x972-w82m-gqc5 / CVE-2026-10599](https://github.com/advisories/GHSA-x972-w82m-gqc5), Event Booking Manager ticket price [GHSA-3qf4-97w4-w66g / CVE-2026-16067](https://github.com/advisories/GHSA-3qf4-97w4-w66g), Simple Membership merchant binding [GHSA-rx87-886c-g6fw / CVE-2026-14936](https://github.com/advisories/GHSA-rx87-886c-g6fw), WPC Name Your Price Select-mode allowlist [GHSA-fqcg-6x27-fj7j / CVE-2026-16620](https://github.com/advisories/GHSA-fqcg-6x27-fj7j), WP Hotel Booking quantity/total and notification checks [GHSA-9rjp-x5g7-g983 / CVE-2026-15149](https://github.com/advisories/GHSA-9rjp-x5g7-g983) and [GHSA-gr3g-w52p-ff6r / CVE-2026-15152](https://github.com/advisories/GHSA-gr3g-w52p-ff6r), Five Star Restaurant Reservations notification binding [GHSA-4prh-qcrv-cpfg / CVE-2026-15147](https://github.com/advisories/GHSA-4prh-qcrv-cpfg), Events Made Easy token-to-payment binding [GHSA-655w-h872-387j / CVE-2026-14842](https://github.com/advisories/GHSA-655w-h872-387j), RegistrationMagic capture binding and replay [GHSA-x5h9-fc29-gm85 / CVE-2026-15208](https://github.com/advisories/GHSA-x5h9-fc29-gm85), Formidable Forms subscription status [GHSA-ww4h-86qv-rmr8 / CVE-2026-11361](https://github.com/advisories/GHSA-ww4h-86qv-rmr8), WP Travel Engine merchant/amount checks [GHSA-v4gx-m8c5-cqwv / CVE-2026-12501](https://github.com/advisories/GHSA-v4gx-m8c5-cqwv), CoCart public price authority [GHSA-2xcr-jvj8-gv2p / CVE-2026-10524](https://github.com/advisories/GHSA-2xcr-jvj8-gv2p), GetPaid Worldpay notification authenticity [GHSA-w426-cmgx-r837 / CVE-2026-12901](https://github.com/advisories/GHSA-w426-cmgx-r837), and Payment Plugins for PayPal route authorization [GHSA-frpp-mq58-xvp7 / CVE-2026-13399](https://github.com/advisories/GHSA-frpp-mq58-xvp7).

Use one disconnected WooCommerce lab, local provider adapter, two synthetic orders/bookings A/B, cheap/expensive catalog fixtures, merchants M1/M2, currencies C1/C2, and no-op paid/fulfillment/ticket/membership sinks. Test these dimensions independently:

| Dimension | Controls |
| --- | --- |
| catalog arithmetic | configured/minimum duration, allowed price set, quantity sign/range, unit price, discounts, computed total |
| local object | order, booking, registration, invoice, membership, subscription, owner, current lifecycle state |
| provider proof | authenticity, provider transaction/capture/token, merchant/payee, amount, currency, status, purpose, expiry |
| consumption | first use, replay against A, crossover to B, concurrent reuse, already-paid/refunded/cancelled state |

Patch gateway HTTP, persistence, inventory, email, ticket, download, membership, and paid-state operations. Capture browser fields, normalized numeric values, server-derived catalog tuple, local provider response, canonical object tuple, proof-consumption state, and no-op transition. Exercise zero, negative, fractional, omitted, duplicate, oversized, below-minimum, cheap-proof/expensive-object, wrong-merchant, wrong-currency, pending/failed, replayed, and corrected-build cases.

The positive is **caller-selected commerce value or authentic proof valid only for tuple A -> server does not re-derive/bind the complete tuple -> mismatched synthetic object reaches a no-op paid/confirmed/fulfillment sink**. Never contact a gateway, create a scannable ticket, activate a real membership, reserve inventory, or claim financial loss from arithmetic alone.

### Treat shortcode parsing as a whole-input grammar

[Easy Appointments GHSA-m9g2-wqhj-c2j4 / CVE-2026-14225](https://github.com/advisories/GHSA-m9g2-wqhj-c2j4) and [Ninja Forms GHSA-2xwp-m9v6-767p / CVE-2026-15256](https://github.com/advisories/GHSA-2xwp-m9v6-767p) describe two routes into WordPress shortcode execution: a contributor-controlled block action that checks only the first tag while rendering the entire string, and anonymous query-string prefill interpreted as a shortcode when a public form uses that value as a default.

Register one lab-only shortcode that increments a recorder and returns a plain random marker. It must not read files/options/users, call the network, mutate state, or execute code. For Easy Appointments compare one approved shortcode, approved-plus-second-canary, denied-first-plus-approved, nested/escaped forms, contributor/administrator, and fixed builds. Preserve raw string, first-tag validator result, full parser token list, and recorder calls. For Ninja Forms compare literal defaults, query prefill disabled/enabled, missing/random/form nonce states, URL encoding, duplicate fields, anonymous/authenticated callers, and fixed builds.

Safe positives are **validator approves first tag -> a second caller-controlled canary shortcode reaches the renderer**, or **anonymous query value -> configured public default-value path -> canary shortcode recorder increments**. Do not invoke installed operational shortcodes or infer command/file/database impact from generic shortcode reachability.

### Bind protected content to the selected course or route family

[Tutor LMS GHSA-6p9h-wm5r-xwmr / CVE-2026-14306](https://github.com/advisories/GHSA-6p9h-wm5r-xwmr) describes enrollment in one course satisfying access checks for another course's lesson, quiz, or assignment. [Passster GHSA-wqxf-2hrv-jrwq / CVE-2025-15674](https://github.com/advisories/GHSA-wqxf-2hrv-jrwq) describes low-role core REST access to globally protected content.

Create public course/post A and protected course/post B containing only random markers. Give one subscriber enrollment/access to A only. Cross current user, enrollment, parent course, lesson/quiz/assignment ID, post ID, frontend route, core REST detail/collection/search/embed route, and plugin protection mode one field at a time. Patch serializers to return only marker IDs. A positive requires **A-scoped enrollment or low-role content capability -> alternate B selector/route -> B marker reaches the serializer without B-specific enrollment/protection authorization**. Never return paid lessons, quiz answers, assignments, real protected posts, author details, or user data.

## August 8 follow-up: bind WordPress file, API, workflow, and commerce authority

An August 8 unreviewed wave adds reusable checks where a public nonce, low-role account, API key comparison, guest cookie, file path, object ID, or client price is mistaken for the final authority:

- AI Engine local-file-to-provider relay [GHSA-hgr8-39c9-344p / CVE-2026-16955](https://github.com/advisories/GHSA-hgr8-39c9-344p) and guest-upload deletion binding [GHSA-rv7j-gq5m-787c / CVE-2026-16953](https://github.com/advisories/GHSA-rv7j-gq5m-787c);
- WP Directory Kit settings/secret disclosure, contact-message scope, query construction, and unpublished user/listing scope [GHSA-jw73-w93j-56gr / CVE-2026-16594](https://github.com/advisories/GHSA-jw73-w93j-56gr), [GHSA-cgfm-pc65-3h3w / CVE-2026-16590](https://github.com/advisories/GHSA-cgfm-pc65-3h3w), [GHSA-hf26-5fpg-7r9w / CVE-2026-16589](https://github.com/advisories/GHSA-hf26-5fpg-7r9w), and [GHSA-42rf-5p25-qxgw / CVE-2026-16595](https://github.com/advisories/GHSA-42rf-5p25-qxgw);
- Solace Extra low-role site-wide settings and imported-content mutation [GHSA-pxjh-xm4v-xwq9 / CVE-2026-16948](https://github.com/advisories/GHSA-pxjh-xm4v-xwq9);
- Dokan cross-vendor downloadable-product grant [GHSA-9qg2-vxvm-6fvv / CVE-2026-16574](https://github.com/advisories/GHSA-9qg2-vxvm-6fvv);
- Newsletters optional-API key type confusion and public-form deserialization [GHSA-5mfh-c59g-8688 / CVE-2026-16269](https://github.com/advisories/GHSA-5mfh-c59g-8688) and [GHSA-jxc3-pfg8-hv86 / CVE-2026-16267](https://github.com/advisories/GHSA-jxc3-pfg8-hv86);
- AI Copilot public workflow-to-account action [GHSA-gjfv-xm8w-qq69 / CVE-2026-14526](https://github.com/advisories/GHSA-gjfv-xm8w-qq69); and
- Appointment Hour Booking client-selected final price [GHSA-r9q4-xcm5-g5ww / CVE-2026-16282](https://github.com/advisories/GHSA-r9q4-xcm5-g5ww).

Confirm the exact plugin slug, affected version, enabled optional feature, rendered shortcode/widget, route/action, role, and corrected behavior. Use a disposable site, synthetic users and objects, fake API/provider values, mocked mail/provider/gateway transports, and patched read, delete, query, workflow, account, deserialization, download-grant, and commerce sinks. Never read configuration or user messages, forward file bytes to a real AI provider, delete retained uploads, send email, create an administrator, grant access to paid files, instantiate a gadget, or complete a booking.

### Keep local file selection separate from provider delivery

For AI Engine, seed an approved upload-root file and a sibling canary containing only a random marker. Configure a fake provider and replace local reads plus outbound request construction with recorders. Compare administrator, subsite administrator on multisite, subscriber, anonymous, public-API enabled/disabled, expected attachment ID, relative path, absolute path, encoded separators, sibling-prefix path, and symlink controls.

Capture raw selector, decoded/canonical path, site/network root, capability decision, public-API state, read-recorder argument, provider identity, outbound field name, and whether canary bytes would enter the body. A bounded positive is **low-role caller -> canonical sibling canary reaches denied reader -> mocked provider body builder selects that file**. Path reachability alone proves file-authority drift; off-host exfiltration requires the separate mocked outbound-body edge. Do not read `wp-config.php`, network configuration, keys, logs, or another tenant's upload.

### Cross guest sessions and upload objects independently

Create guest sessions A/B and synthetic uploads A/B. Hash all cookie/session and file references in evidence. Cross session cookie, upload owner, file reference, route nonce, expiry, and delete target one field at a time while replacing deletion with a no-op recorder.

The secure tuple is **guest session + upload capability + canonical file object + owner + purpose + expiry**. The positive is **A's cookie plus caller-selected B reference -> B reaches the delete recorder without a server-side B ownership decision**. Merely obtaining both opaque values or receiving a success-shaped response is insufficient, and no file should be deleted.

### Compare nonce possession with capability and object authorization

Use subscriber A, vendor A, customer A, foreign vendor/product B, synthetic WP Directory Kit messages/listings/settings, imported site-builder object B, and no-op serializers/mutators.

| Surface | Weak proof to vary | Required final binding | Safe evidence |
| --- | --- | --- | --- |
| WP Directory Kit AJAX | logged-in state or nonce | route capability plus message/listing/settings owner and field allowlist | synthetic B marker or fake credential field selected by recorder |
| Solace Extra AJAX | nonce visible on low-role admin page | site-wide configuration/import-management capability plus canonical object | reversible marker reaches write/delete recorder |
| Dokan download grant | authenticated vendor and order route | downloadable product belongs to vendor, order/customer is eligible, price/payment state is valid | B's synthetic download ID reaches no-op grant recorder |

Test anonymous, subscriber/vendor owner, low-role non-owner, expected manager, stale/random nonce, object A/B, nonexistent object, duplicate parameters, and fixed-build controls. Preserve the canonical object and principal at both guard and sink. Never serialize API keys, contact messages, user data, unpublished listing content, paid file bytes, or customer/order details; marker IDs are enough.

For the WP Directory Kit query record, intercept the final SQL before execution. Send only delimiter-shaped inert values and compare prepared/bound controls. Capture raw input, sanitization, query template, bindings, parser-token diff, role, and selected object scope. Do not run extraction, timing, stacked-statement, file, or destructive payloads.

### Treat API keys as typed, exact secrets

Enable the Newsletters API only in an isolated lab and seed a random fake key. Patch subscriber mutation and email delivery. Exercise absent, null, Boolean, integer, zero-like, empty string, numeric string, array/object, duplicate parameter, wrong random string, and exact-key controls through every accepted body/query/header representation.

Record request decoder type, normalization, comparison operator/result, selected API action, and denied mutation/mail sink. The bounded positive is **non-string or wrong synthetic key -> loose comparison succeeds -> privileged API action reaches the no-op sink**. Do not modify subscriber rows or send messages. A route that parses the request but rejects before the privileged action is not an authentication bypass.

### Prove public-form deserialization without a POP chain

Instrument `unserialize()` and object construction in the Newsletters public form path. Submit only an inert serialized fixture naming a lab class with no magic methods. Record route exposure, form/nonce state, raw-input hash, allowed-class policy, selected class, and patched constructor event. The bounded result is **anonymous form field -> unrestricted class selection at the deserializer recorder**. Do not inventory production classes, instantiate a gadget, invoke magic methods, or claim code execution from deserialization reachability alone.

### Public nonce is not workflow authority

For AI Copilot, render the relevant shortcode or public chatbot on a disposable page and record whether ordinary frontend JavaScript publishes `WAIC_DATA.waicNonce`. Replace workflow execution, user creation, role assignment, and persistence with denied recorders. Compare missing/random/public nonce; feature absent/present; anonymous/subscriber/administrator; allowed inert workflow node; unknown node; and an account-action node whose requested role is a harmless custom canary role.

Capture nonce provenance, route authentication, workflow ownership/trust state, node allowlist, action registry lookup, requested account fields/role, and denied sink. A safe positive is **logged-out visitor receives ordinary frontend nonce -> caller-supplied workflow selects an account-action node -> no-op account/role recorder receives the canary request without an administrative capability decision**. Do not submit `administrator`, create an account, execute an operational node, or call external tools. Site takeover is the advisory's claimed impact; the wiki proof stops at the denied authority sink.

### Recompute booking price from the server-owned service

For Appointment Hour Booking, create services A/B with different synthetic configured prices and use a local payment adapter. Patch booking persistence, payment, email, calendar, and fulfillment. Vary service ID, owner, duration, quantity, discounts, currency, and client-supplied final price independently, including omitted, zero, negative, fractional, duplicate, oversized, expected, and A-price/B-service crossover values.

Record browser price, parsed numeric representation, canonical service/rate, server-derived total, currency, final persisted tuple, and no-op booking/payment sink. The positive is **caller price differs from server-derived total -> caller value becomes authoritative -> mismatched synthetic booking tuple reaches the recorder**. Do not create a booking or payment, reserve a slot, send email, or infer completed underpayment from arithmetic alone.

The same wave's reflected/stored markup, SVG upload, analytics/user-list disclosure, log-inflation, and generic low-role settings records were source-tracked without separate workflows because the existing render, upload, object-scope, and mutation matrices already provide equivalent safe sinks.

## August 9 follow-up: bind alternate routes, remote-management proofs, and selectors to final authority

Five newly published unreviewed records extend the existing WordPress matrices:

- Create public REST render/publish routes [GHSA-m73c-99g6-hrp8 / CVE-2026-18037](https://github.com/advisories/GHSA-m73c-99g6-hrp8) and [GHSA-66mx-cjh4-m7cx / CVE-2026-16992](https://github.com/advisories/GHSA-66mx-cjh4-m7cx);
- WP MAPS PRO public AJAX file inclusion [GHSA-mcpf-p8j2-92hw / CVE-2026-18465](https://github.com/advisories/GHSA-mcpf-p8j2-92hw);
- WP Data Access front-end form column selection [GHSA-chrp-6wq4-c4qg / CVE-2026-18032](https://github.com/advisories/GHSA-chrp-6wq4-c4qg);
- InfiniteWP Client multisite connection binding [GHSA-5r79-75x7-rrwq / CVE-2026-15038](https://github.com/advisories/GHSA-5r79-75x7-rrwq); and
- PiWeb previous-order-to-cart selection [GHSA-39g4-r8qh-2jjf / CVE-2026-18603](https://github.com/advisories/GHSA-39g4-r8qh-2jjf).

Confirm exact plugin slug, affected version, route/action registration, multisite/configuration preconditions, and corrected behavior. Use only disposable sites, synthetic drafts/orders/forms/users, fake management keys, and patched publish, include, query, session, and cart sinks.

### Build one route-family and side-effect matrix

For Create, seed public post A and private draft B with random marker IDs. Enumerate every plugin REST route that renders, returns, previews, or generates content. Cross anonymous, subscriber, author, owner, and expected manager with A/B/nonexistent IDs and GET/POST plus alternate route families. Patch content serialization and publication-status mutation separately.

The bounded positive is **anonymous alternate route selects draft B -> B's marker reaches a no-content serializer -> the same request reaches a no-op publish-state sink without B-specific authorization**. Report disclosure selection and publication mutation as separate edges. Never return draft bodies or make retained content public.

### Treat dispatch operation and file path as separate capabilities

For WP MAPS PRO, capture the public AJAX action, operation/dispatch selector, path parameter, capability decision, canonical target, include decision, and denied include sink. Use an inert in-root PHP fixture whose body is never executed plus a sibling plain-text canary. Compare omitted/unknown/expected operations, raw and encoded separators, absolute paths, stream-wrapper-shaped values rejected before use, existing/dangling symlinks, and fixed builds.

A safe positive is **anonymous action -> caller selects an include-capable operation -> canonical sibling canary reaches the denied include sink**. Do not include PHP, WordPress configuration, plugin files, logs, credentials, or host files, and do not claim code execution from path selection alone.

### Preserve identifier grammar through generated SQL

For WP Data Access, create a front-end form bound only to a synthetic table with public column `label` and private canary column `internal_marker`. Replace database execution with a query recorder and serializer with an ID-only result. Vary field/column selectors, aliases, expression-shaped inert delimiters, duplicates, arrays/objects, case, quoting, qualified names, nonexistent fields, table crossover, nonce scope, and fixed builds.

Capture route authentication, nonce provenance and covered fields, form/table binding, raw selector, validated identifier, generated SQL, parser tokens, bindings, and selected output schema. The positive is **anonymous form proof -> caller-selected column outside the form allowlist changes query structure -> query recorder selects `internal_marker`**. Do not bind the fixture to `wp_users`, request hashes, execute extraction/timing syntax, or retain query results.

### Bind remote-management enrollment to one installation and network

For InfiniteWP Client, use a disposable WordPress Multisite network, fake controller identity/key material, and patched key-binding plus session-cookie setters. Compare unconnected, partially connected, and connected states; single-site versus multisite; network/site administrator targets; omitted, malformed, foreign, replayed, and correctly signed fake requests; site/network IDs; and corrected builds.

Preserve **installation/network identity + controller identity + key + enrollment state + request authenticity + target principal + purpose + replay state**. A bounded positive is **unconnected or mismatched fake controller request -> attacker key reaches the binding recorder -> later fake proof reaches a network-administrator session recorder**. Do not create a usable session, install code, or retain key material; key binding and session selection are separate claims.

### Keep previous-order lookup separate from cart mutation

Create users A/B, orders A/B with distinct marker item IDs, and carts A/B. Patch order serialization, cart clear, and cart add operations. Cross logged-out/logged-in browser, order ID, order owner, cart/session, nonce, referrer, order state, and item visibility one field at a time. Include a crafted-link navigation control without using real customers.

The bounded positives are **anonymous request selects foreign order B -> B's marker IDs reach the no-content serializer** and **cross-site navigation -> logged-in A's cart clear/add recorders receive B-derived marker items without A authorizing the transition**. Do not expose billing details, order contents, customer identities, or mutate a retained cart.

## August 10 follow-up: bind authentication, fetch, file, and commerce authority at the final sink

An August 10 unreviewed wave adds useful variants to the existing WordPress matrices:

- alternate authentication and global REST-filter scope: Block User Account application-password access [GHSA-c64r-rhpr-pqr5 / CVE-2026-18960](https://github.com/advisories/GHSA-c64r-rhpr-pqr5), CheckView URI-substring authentication suppression [GHSA-8r6g-r9rq-8jr8 / CVE-2026-18786](https://github.com/advisories/GHSA-8r6g-r9rq-8jr8), and AutoNetTV Relay scheduled-task session creation [GHSA-qvph-jjx5-pw4h / CVE-2026-13600](https://github.com/advisories/GHSA-qvph-jjx5-pw4h);
- password-reset subject, verifier, and attempt-bucket binding: Login & Register Forms [GHSA-53xf-4rjw-hxg5 / CVE-2026-18469](https://github.com/advisories/GHSA-53xf-4rjw-hxg5), [GHSA-gxm4-76w3-xhp8 / CVE-2026-18470](https://github.com/advisories/GHSA-gxm4-76w3-xhp8), and [GHSA-77w2-vfvm-8c9g / CVE-2026-18468](https://github.com/advisories/GHSA-77w2-vfvm-8c9g), plus BricksForge form-action password change [GHSA-3w5j-v478-4p9q / CVE-2026-18030](https://github.com/advisories/GHSA-3w5j-v478-4p9q);
- public fetch and response-relay authority: All-in-One Video Gallery download relay [GHSA-65rp-7r2j-rmm6 / CVE-2026-19075](https://github.com/advisories/GHSA-65rp-7r2j-rmm6) and Podcast Player RSS fetch [GHSA-fx75-97x2-v9j2 / CVE-2026-14860](https://github.com/advisories/GHSA-fx75-97x2-v9j2);
- file and upload authority: Product Input Fields empty accepted-type policy [GHSA-76cm-vw34-ffw7 / CVE-2026-19089](https://github.com/advisories/GHSA-76cm-vw34-ffw7), Contact Form to Any API predictable public copy [GHSA-qp64-vw92-jr32 / CVE-2026-18946](https://github.com/advisories/GHSA-qp64-vw92-jr32), and File Manager low-role read/delete commands [GHSA-mr78-php7-96p9 / CVE-2026-17540](https://github.com/advisories/GHSA-mr78-php7-96p9);
- booking, OAuth, and payment object binding: Salon Booking System booking read/callback/mutation records [GHSA-pf8j-pw7h-gqgp / CVE-2026-17020](https://github.com/advisories/GHSA-pf8j-pw7h-gqgp), [GHSA-3hmc-2cg9-g3wx / CVE-2026-17023](https://github.com/advisories/GHSA-3hmc-2cg9-g3wx), [GHSA-jf35-5rcj-7rqm / CVE-2026-17021](https://github.com/advisories/GHSA-jf35-5rcj-7rqm), and [GHSA-9jp6-8vxq-2865 / CVE-2026-17022](https://github.com/advisories/GHSA-9jp6-8vxq-2865); and
- server-owned commerce tuples: PayPal merchant and amount checks [GHSA-645w-cxcg-9mjc / CVE-2026-17012](https://github.com/advisories/GHSA-645w-cxcg-9mjc) and [GHSA-3gq9-83xc-rrc7 / CVE-2026-17016](https://github.com/advisories/GHSA-3gq9-83xc-rrc7), Pinpoint booking price [GHSA-2jwj-8g7h-f5p5 / CVE-2026-15229](https://github.com/advisories/GHSA-2jwj-8g7h-f5p5), and MotoPress payment-record creation [GHSA-vqh4-pqm8-4r46 / CVE-2026-15237](https://github.com/advisories/GHSA-vqh4-pqm8-4r46).

Confirm exact plugin slug, affected version, enabled feature, route/action, role, and corrected behavior. These records were unreviewed when scanned; treat them as test seeds, not independent proof of exposure. Use disposable sites, two-user synthetic objects, owned no-content peers, fake provider/payment values, and patched session, password, network, response, file, booking, and paid-state sinks.

### Compare every authentication path after account state changes

Create synthetic user A with password, application password, cookie, and any plugin-specific authentication route. Block or revoke A through the plugin while replacing session issuance and REST mutation with recorders. Compare browser login, XML-RPC if enabled, core REST, application-password REST, plugin REST, scheduled-task routes, and exact versus prefix/suffix/substring request paths. Preserve account state, credential type, route family, global authentication-filter result, canonical route, and final principal.

A bounded positive is **blocked or anonymous principal -> alternate credential/route or over-broad URI match clears the authentication error -> A reaches a harmless REST mutation recorder**, or **public scheduled-task request -> administrator identity reaches a denied cookie setter**. Do not mint a usable cookie, invoke operational cron work, or change account data. A successful HTTP status without a privileged sink is not an authentication bypass.

### Bind reset proof, subject, browser, and attempt budget as one tuple

Create users A/B with sink-only mailboxes. Patch password writes and sessions. Vary requested account, response-selected client key, verification code, initiating browser/session, source identifier, attempt counter key, expiry, purpose, duplicate fields, and the user supplied at the final reset action. Include wrong-code exhaustion followed by caller-key rotation and A-proof/B-subject crossover.

The required tuple is **subject + destination + initiating browser/session + verifier + attempt bucket + purpose + expiry + single-use state**. A safe positive is **proof or budget established for A/context A -> caller changes one selector -> B reaches the denied password sink**, or **failed attempts under one caller key -> caller rotates that key -> the same subject receives a fresh budget**. Never send mail externally, set a usable password, or create a session.

### Separate fetch destination, response relay, and parser acceptance

For both download and RSS-style handlers, configure only owned peers: a public no-content origin, an owned redirector, and a synthetic denied destination that returns a random marker. Patch DNS resolution, socket connect, redirect handling, body reads, XML parsing, and response streaming independently. Cross stored post metadata versus request URL, schemes, userinfo, ports, redirects, hostname case/trailing dot, address families, duplicate parameters, response types, and fixed builds.

Capture initial URL, each redirect, resolved address set, connected peer, response bytes hash, parser decision, and downstream relay. Report the narrowest proven edge: **anonymous selector -> denied connector**, **owned redirect -> denied final peer**, or **synthetic marker -> public response recorder**. Destination control is not response disclosure, and XML acceptance is not arbitrary-byte relay. Never contact metadata, loopback, private, customer, or production services.

### Trace upload and file authority to distinct final operations

Use a disposable upload root with one benign image-like canary, a dangerous-looking but inert extension marker, and a sibling file whose contents are never opened. Test omitted, empty, wildcard, and explicit accepted-type settings separately from MIME, original filename, stored extension, generated name, canonical destination, and public URL. For public contact-form copies, submit two synthetic uploads with colliding or predictable names and patch copy/open/stream operations.

For File Manager, build a matrix across list, metadata, read, copy, move, overwrite, and delete using owner A/B and canonical in-root/sibling paths. Replace every final filesystem operation with a denied recorder. Positives require **policy accepts caller-selected type/name -> inert file reaches a public/executable-path write recorder**, **A can predict/select B's upload -> B reaches a response recorder**, or **low-role command -> sibling target reaches a denied operation sink**. Never upload PHP, open `wp-config.php`, disclose form submissions, or delete files.

### Keep booking identity, OAuth proof, and paid state separate

Create customers A/B, bookings A/B, and a fake calendar/provider integration. Cross login/session, booking ID, booking ownership token, requested total, OAuth `state`, initiating browser, provider account, callback code, stored integration owner, and mutation type. Patch booking serializers, total updates, provider token exchange, and configuration writes. A reportable result is one specific edge: foreign booking marker selected, foreign booking reaches a no-op mutation, or callback proof from browser A replaces the site's fake integration without an A-bound state decision.

For commerce, record **local object + merchant/payee + amount + currency + provider transaction + status + payment method + purpose + replay state**. Use only mocked provider responses and no-op payment/booking sinks. Test wrong merchant, partial/zero/negative/duplicate amount, pending/failed status, proof from order A against order B, caller-created completed records, and replay. A positive requires a mismatched tuple to reach the paid/approved recorder; never contact a gateway, reserve inventory, or create a retained payment.

## August 23 follow-up: bind registration role selection, permission-filter rewrites, and invoice-file selectors to final authority

An August 23 unreviewed WordPress wave adds useful variants to the existing matrices:

- registration role selection: RestrictMate role restriction bypass, unauthenticated administrator-account creation [GHSA-vmqg-pqj8-5w8h](https://github.com/advisories/GHSA-vmqg-pqj8-5w8h);
- permission-filter rewrites over core REST handlers: Security Hardener `rest_endpoints` filter overwrites every `/wp/v2/users` handler's `permission_callback` with a bare `is_user_logged_in` closure, stripping `create_users`/`promote_user`/`edit_users`/`delete_users` [GHSA-493r-g3qv-5457](https://github.com/advisories/GHSA-493r-g3qv-5457);
- publication capability drift: Content Mask Contributor-level publish of the selected post type without the `publish` capability [GHSA-mfj2-2xr8-6w24](https://github.com/advisories/GHSA-mfj2-2xr8-6w24);
- AJAX capability and nonce gaps: WooCommerce Bookings AJAX action without capability check, nonce bypass by omission, Subscriber-level draft bookable-product creation [GHSA-jfpw-hmq2-3xwx](https://github.com/advisories/GHSA-jfpw-hmq2-3xwx);
- invoice-file base64 selector: WebToffee PDF Invoices `get_image_src_in_base64` directory traversal, subscriber-level arbitrary-file read embedded in cached invoice HTML served by the plugin's own Print/Download endpoints [GHSA-7r74-667v-4q77](https://github.com/advisories/GHSA-7r74-667v-4q77); and
- deserialization of a role-list parameter: PPWP Password Protect Pages PHP object injection from `post_protection_roles`, Contributor and above, impact gated on a co-resident POP chain [GHSA-fgg6-3rw5-h3j8](https://github.com/advisories/GHSA-fgg6-3rw5-h3j8).

Confirm exact plugin slug, affected version, enabled feature (Security Hardener's block-user-enum is on by default), route/action, and role before testing. These records were unreviewed when scanned; treat them as test seeds, not independent proof of exposure.

### Select the role on the server, not in the registration form

For registration-role records, create no real accounts: patch the user-insertion sink with a recorder that captures the requested role and denies the write. Submit registration forms with the role field omitted, empty, a known role, an administrator role, and encoded variants on the affected plugin. A bounded positive is **unauthenticated registration request with caller-selected administrator role -> user-insertion recorder observes the administrator role assignment**. Never complete a real registration or mint a session.

### Rewrite the permission decision, not the endpoint table

For Security Hardener-style `rest_endpoints` filter rewrites, register the affected filter in a lab install with a patched capability check that records which handler closure it installed. Enumerate every route family the filter touches (core users plus any plugin routes), every method, and the original versus installed `permission_callback`. Patch the capability check with a recorder. A bounded positive is **subscriber request -> original capability check bypassed -> denied capability recorder on a core user-creation or password-reset handler**. Record the exact filter, the stripped capabilities, and the default-enabled option that activates the rewrite.

### Keep the base64 file selector out of the invoice root

For WebToffee-style image selectors, use a disposable upload root with marker files inside and a sibling marker file outside whose contents are never opened by the control path. Patch file reads with a recorder and drive the Print/Download invoice endpoints with a valid synthetic nonce and access key, varying the image source parameter (literal, encoded, and prefix-anchored traversal). A bounded positive is **subscriber request with caller-selected source -> denied read recorder observes an out-of-root target** and the marker content would reach the cached invoice HTML. Never read `wp-config.php` or credential files.

### Prove deserialization separately from gadget availability

For PPWP-style object injection, record the exact parameter, codec, and authenticated role floor, and patch the unserializer with a recorder that captures the incoming object graph shape and denies instantiation of any class. A bounded positive is **Contributor request -> recorder observes an attacker-shaped object at the deserialization sink**. State POP-chain availability as a separate untested precondition; never instantiate a gadget chain.

## September 16 follow-up: treat a delegated import/export capability as untrusted input at every final sink

A September 16 unreviewed wave around **WP Import Export Lite** before 3.9.33/3.9.34 is the cleanest illustration yet that an admin-delegated import/export capability is a full execution surface, because the plugin lets the capability holder steer *which code runs and where files land*:

- arbitrary PHP function applied to exported field values -> RCE: [GHSA-v7v7-79q5-j8cf / CVE-2026-76551](https://github.com/advisories/GHSA-v7v7-79q5-j8cf);
- user-supplied export output path writes arbitrary filenames to arbitrary locations -> RCE: [GHSA-g78q-54w3-px42 / CVE-2026-76550](https://github.com/advisories/GHSA-g78q-54w3-px42);
- unvalidated stored path fed to a recursive directory delete, reaching outside the web root: [GHSA-j4q7-794x-44pp](https://github.com/advisories/GHSA-j4q7-794x-44pp);
- files retrieved from a user-supplied URL during import with no type/extension/content validation, storing executable files: [GHSA-mq5q-9p83-hr98 / CVE-2026-76552](https://github.com/advisories/GHSA-mq5q-9p83-hr98);
- import-time URL requests to internal hosts with responses readable by the requester, explicitly an **incomplete fix for CVE-2026-11397**: [GHSA-49j8-gcx6-2f92](https://github.com/advisories/GHSA-49j8-gcx6-2f92); and
- export filter values interpolated into SQL: [GHSA-fxvp-m8p8-32p6 / CVE-2026-76556](https://github.com/advisories/GHSA-fxvp-m8p8-32p6).

Two durable lessons:

1. **Enumerate delegated-capability surfaces as first-class RCE candidates.** On any site where an administrator can grant a plugin's import/export permission to a lower role, inventory the five sink classes the capability reaches — callback/function name, output path, delete path, fetched URL, and query fragment — with a recorder-patched lab install. A bounded positive is e.g. **export-capable low-role request with a callback-name field -> patched function-invocation recorder receives a denied marker name**, or **output-path parameter -> denied write recorder observes an out-of-root canonical path**. Never invoke a real dangerous function, never write or delete outside a disposable root, and never target internal services (use an owned no-content peer).
2. **Re-test vendor fixes on the same route.** The import-URL record is an incomplete fix of an earlier CVE. When a plugin has a security history for one route, diff the fix and re-run the original SSRF/upload matrix against the same handler — scheme allowlists that miss redirect-following, DNS-rebinding, and protocol wrappers are the usual residual gaps (see the existing SSRF canonicalization workflow).

Adjacent records from the same wave, processed without publication: Subscriptions for WooCommerce shared-secret validation gap exposing subscriptions to unauthenticated callers [GHSA-mp62-wj23-fc7f](https://github.com/advisories/GHSA-mp62-wj23-fc7f) (secret-comparison hygiene, axis already on commerce-proof pages); Ni WooCommerce Sales Report unauthenticated SQLi and unauthenticated order/customer lookup in report-printing [GHSA-32fm-vvf7-rmhw](https://github.com/advisories/GHSA-32fm-vvf7-rmhw) / [GHSA-4p9c-cw99-phxx](https://github.com/advisories/GHSA-4p9c-cw99-phxx) (unauthenticated report routes, axis already covered); and the routine missing-capability/nonce WooCommerce plugin singles (Rox Appointment Booking, WPBot, FluentBoards, LearnPress, kboard, MultiVendorX, Schema & Structured Data, Visualizer, Newsletter redirect, Seraphinite Accelerator, Subscriptions CSRF, WP Import Export Lite XSS singles).

## September 16 follow-up: per-item validation, payment-to-order binding, and request-derived shortcode execution

Three September 16 unreviewed records extend axes already on this page:

- **Appointment Hour Booking before 1.5.95** [GHSA-cqfw-wgfw-rqrw / CVE-2026-86475](https://github.com/advisories/GHSA-cqfw-wgfw-rqrw): a multi-appointment booking submission does not re-check *every* appointment against the capacity configured for its own slot, letting unauthenticated visitors take fully booked slots. The generalization is a batch-request pattern that is useful across all bulk/line-item endpoints: when one submission carries N items, verify the server validates **each item against its own parent configuration** rather than checking the first item, the aggregate count, or a single representative slot. Harness: two disposable slots, one with capacity 1 already filled by a synthetic booking; submit a batch containing the full slot plus an open slot; the finding is the full slot accepting the extra marker booking. Restore the canary booking state immediately.
- **Eventin before 4.1.24** [GHSA-8p6x-g49r-wjj7 / CVE-2026-84906](https://github.com/advisories/GHSA-8p6x-g49r-wjj7): a completed payment is confirmed only as "gateway says success" — amount, currency, and which order the transaction belongs to are not verified — so replaying one genuine low-value payment marks unpaid orders of any value as paid. This is the same transaction-binding failure as the pretix GiroCheckout replay above, reached through a different route: the earlier Eventin record was a client-selected paid *status*; this one is a *provider-verified* transaction applied to the wrong order, which is more dangerous because it passes naive webhook-signature checks. Extend the two-order replay harness: complete order A through a mocked gateway, then replay A's success payload at B's confirmation handler while varying local order ID, provider transaction ID, amount, and currency one field at a time. The bounded positive is **authentic success for synthetic order A (low amount) -> replay -> order B (any amount) reaches paid marker**. Never contact a real gateway or reuse a real transaction.
- **Formidable Forms before 6.35** [GHSA-hgfq-v6h8-89x5 / CVE-2026-19857](https://github.com/advisories/GHSA-hgfq-v6h8-89x5): a request-derived value reaches the WordPress shortcode parser during token substitution into a form's custom HTML, so unauthenticated visitors cause arbitrary shortcodes **with attacker-chosen attributes** to execute server-side on any page displaying the affected form. This is the input-to-interpreter class the SendPulse renderer section covers from the storage side; here the untrusted value is the *request*, and the interpreter is `do_shortcode()` rather than an HTML sanitizer. Audit rule: on any form builder, check whether entry values, email-body fields, or confirmation-HTML tokens are interpolated through shortcode processing, and prove with one harmless display-only shortcode that writes a unique marker (e.g. a marker via `[caption]`/custom test shortcode) — record raw input, substituted template state, parsed shortcode/attributes, and rendered output separately. Do not use file-read, SMTP, admin, or file-upload shortcodes as the proof, and do not claim RCE unless a separately authorized executable shortcode sink is shown.

Adjacent records from the same wave processed without publication: Royal Elementor Addons pre-1.7.1067 sanitize/escape gap (routine stored-XSS hygiene, axis already covered), and the routine Linux-kernel/Unbound/appliance singles handled on the Pepperl+Fuchs/Arista page this run.

## Reporting checklist

Include:

- exact product/plugin slug, version or firmware, configuration state, route/action, method, and authentication context;
- each chain edge as a decision table rather than one inflated impact label;
- intended-root lifecycle state, raw/decoded token, canonical target, containment result, and delete-sink decision for filesystem operations;
- nonce provenance, capability result, selected option or role, request-post owner, target user, global-setting scope, payment/order binding, and resolved virtual path;
- proof subject, initiating browser/session, attempt-bucket key, reset-link authority, immediate network peer, and chosen client identity;
- canonical order/ticket/event owner, parent object, delegated provider authority, recorder action, and idempotency state;
- canonical vendor/course/post/location owner, enrollment/publication state, account-create result, role-policy decision, and final no-op sink subject;
- upload container/member, raw extension and MIME, sanitizer invocation, canonical destination, and public-path write-recorder decision;
- token signature/key decision, issuer/audience/time claims, resolved login subject, and no-op session result;
- authorized attachment ID, path-selected attachment/file, canonical root result, and patched read-sink argument;
- browser, normalized, stored, and gateway-recorder amount representations for payment-integrity checks;
- first-stage metadata write authority, exact inert key hash, later duplicate trigger identity, and recorded SQL token-boundary diff for second-order checks;
- affected and fixed controls, including feature-disabled and unconfigured states;
- configured versus submitted integration identity, commerce tuple, alternate-route permission decision, token/assertion algorithm and key type, reset subject, and final no-op sink;
- decoded/canonical AI file selector, mocked provider body decision, guest-session/upload ownership tuple, typed API-key comparison, workflow-node authorization, and server-derived booking price;
- alternate REST route and publication side effect, dispatch operation plus canonical include target, form-bound column allowlist, remote-controller enrollment tuple, and previous-order/cart ownership;
- alternate authentication route and canonical URI match, reset subject/browser/attempt tuple, initial URL through final peer and response relay, per-operation file target, booking/OAuth ownership tuple, and complete merchant/amount/payment binding;
- hashes or redacted identifiers for fake connection values, payment responses, cookies, and canary files;
- the pretix quick-setup CVE identifier discrepancy and the source attached to each identifier;
- a bounded impact statement that distinguishes option disclosure, session creation, persistent write, DOM rendering, payment replay, event mutation, filesystem read/write, and execution.

Do not infer administrator takeover from option disclosure or a harmless canary-role assignment alone, store compromise from a reversible global setting alone, XSS from stored markup alone, completed underpayment from a local gateway recorder, database disclosure from a SQL grammar diff, free tickets from a callback that did not change order state, or device code execution from filesystem reachability alone.