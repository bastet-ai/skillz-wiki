# Rails Active Storage: unsafe image transformations (command injection risk)

## The pitfall
Rails **Active Storage** can apply image transformations via `variant(...)`.

If you **accept untrusted / user-controlled transformation methods or parameters**, you can create a pathway to **command injection** (or similar RCE primitives), depending on your image processing stack.

A common dangerous pattern is letting request parameters directly influence transformation operations:

```ruby
# DANGEROUS if params are untrusted
image_tag blob.variant(params[:t] => params[:v])
```

This risk is particularly relevant when using `image_processing` with a backend such as **MiniMagick/ImageMagick**, where arguments can have security-sensitive effects.

## Defensive guidance

### 1) Do not pass user input to transformation methods/args
Treat transformation selection as **application logic**, not user-controlled data.

Instead, map user-visible choices to **server-side constants**:

```ruby
ALLOWED_VARIANTS = {
  "thumb" => { resize_to_limit: [200, 200] },
  "hero"  => { resize_to_fill:  [1600, 900] },
}.freeze

key = params[:variant].to_s
transform = ALLOWED_VARIANTS.fetch(key) { ALLOWED_VARIANTS["thumb"] }

image_tag blob.variant(transform)
```

### 2) If you must accept parameters, strictly validate
If there is a legitimate need for user-supplied values (e.g., width/height), validate:

- type (integer)
- range (min/max)
- format (no strings that could be interpreted as options)

Example:

```ruby
w = Integer(params[:w])
raise ArgumentError unless (1..2000).cover?(w)

image_tag blob.variant(resize_to_limit: [w, w])
```

### 3) Run a hardened ImageMagick policy (when applicable)
If your processing backend is ImageMagick, deploy a **restrictive ImageMagick security policy** appropriate for your environment (disable dangerous coders/delegates, remote reads, etc.).

This is *defense-in-depth* — not a substitute for input validation.

### 4) Keep Rails and dependencies patched
Upgrade Rails to versions containing fixes for unsafe defaults / bypasses in transformation allowlists.

## Detection/triage checklist
- Search for `variant(` calls that use `params`, `request`, or other untrusted data.
- Check which image processor is in use (MiniMagick, libvips, etc.).
- Review ImageMagick policy on hosts running transformations.

## References
- GitHub Advisory: GHSA-r4mg-4433-c7g3 (CVE-2025-24293)
- ImageMagick security policy guidance: https://imagemagick.org/script/security-policy.php
