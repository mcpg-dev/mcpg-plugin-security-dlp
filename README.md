# Data-Loss-Prevention Gate — `dev.mcpg.tool-gate.dlp`

> class `tool_gate` · `native` · package `mcpg-plugin-security-dlp` · artifact `libmcpg_plugin_security_dlp.so` · BUSL-1.1

A tool gate that inspects tool arguments before dispatch and tool results after
it, looking for secrets and personal data with a set of built-in regex detectors
plus any patterns you supply. A hit either denies the call or rewrites the
offending substrings, and the matched value itself never reaches a deny message,
error payload, log line or metric label — only detector names and counts. Reach
for it when tool traffic crosses a trust boundary and you want a last-line check
that credentials and PII do not flow through the gateway in either direction.

## What it does
- Scans arguments pre-dispatch and results post-dispatch; each phase can be
  switched off independently.
- Walks every string leaf of the JSON payload, recursing through objects and
  arrays, and collects the distinct detectors that fire.
- Ships seven built-in detectors and compiles operator-supplied
  `custom_patterns` alongside them at load time.
- Gates credit-card matches behind a Luhn checksum so ordinary long digit runs
  do not trip the detector.
- In `block` mode denies with HTTP `403` and JSON-RPC code `-32050`; in `redact`
  mode allows the call and returns rewritten arguments (pre) or a rewritten
  result (post).
- Scopes itself with `tools` / `exclude_tools` glob patterns, where `*` matches
  any sequence and `?` exactly one character, and an exclude always wins.
- Skips non-`tool` surfaces (prompts, resources, completion) unless
  `apply_to_non_tool_surfaces` is on.
- Fails closed: an unparseable config, an unknown config key, or an invalid
  custom regex refuses to load rather than running with a hole in the ruleset.
- Runs entirely in-process. It declares no capabilities, opens no sockets, and
  calls no host services.

## Configuration
Loaded from the flat top-level `plugins:` list. Every `tool_gate` entry joins
one chain evaluated in list order: the first deny short-circuits the call, and
allow-metadata merges across the chain.

```yaml
plugins:
  - id: dev.mcpg.tool-gate.dlp
    class: tool_gate
    source: { path: ./plugins/libmcpg_plugin_security_dlp.so }
    config:
      action: redact
      detectors: [aws_access_key, jwt, email, url_credentials]
      custom_patterns:
        - { name: employee_id, regex: "EMP-[0-9]{6}" }
      redact_placeholder: "[REDACTED]"
      tools: ["*"]
      exclude_tools: ["debug.*"]
```

To pull the published artifact instead of building it, write
`source: { oci: ghcr.io/mcpg-dev/source-code/plugins/tool-gate-dlp:protocol-1 }`.
The reference is platform-agnostic; the gateway resolves the variant for its own
OS, architecture and libc.

| Field | Type | Default | Description |
|---|---|---|---|
| `pre_execution` | bool | `true` | Scan arguments before dispatch. |
| `post_execution` | bool | `true` | Scan results after dispatch. |
| `action` | `block` \| `redact` | `block` | Deny on a finding, or rewrite the offending substrings and continue. |
| `detectors` | array | all seven built-ins | Which built-in detectors to compile. |
| `custom_patterns` | array of `{name, regex}` | `[]` | Extra named patterns, compiled at load. |
| `redact_placeholder` | string | `[REDACTED]` | Replacement text in `redact` mode. |
| `redact_url_credentials` | bool | `true` | In `redact` mode also strip `user:pass@` userinfo from URL-shaped strings. |
| `validate_credit_card_luhn` | bool | `true` | Require a Luhn-valid checksum before a credit-card match counts. |
| `tools` | array of glob | `[]` | Tool names this gate applies to; empty means every tool. |
| `exclude_tools` | array of glob | `[]` | Tool names to skip; an exclude beats an include. |
| `apply_to_non_tool_surfaces` | bool | `false` | Also gate prompt, resource and completion surfaces. |

Built-in detectors, named as they appear in `detectors` and in metric labels:

| Name | Matches |
|---|---|
| `aws_access_key` | AWS access-key identifiers (`AKIA`, `ASIA`, `AROA`, and the other 4-letter prefixes followed by 16 upper-case alphanumerics). |
| `aws_secret_key` | Bare 40-character base64-alphabet runs — the shape of an AWS secret key, and inherently noisy. |
| `jwt` | Three dot-separated base64url segments whose header and payload both begin `eyJ`. |
| `email` | Email addresses. |
| `credit_card` | Runs of 13–19 digits, optionally separated by spaces or dashes, Luhn-checked by default. |
| `generic_api_key` | `api_key` / `secret` / `token` / `password` / `passwd` / `bearer` followed by a 16-character-or-longer value. |
| `url_credentials` | `scheme://user:pass@host` userinfo. |

Unknown fields are rejected.

## Security
- Findings are reported by detector name only. The deny message names the
  detectors that fired, `error_data` carries `{detectors, count}`, the warning
  log carries the same list, and metric labels carry the detector name — none of
  them carry the matched text.
- Redaction is substitution over string leaves: every non-URL detector's matches
  are replaced with `redact_placeholder`, then URL userinfo is stripped
  separately when `redact_url_credentials` is on. Numbers, booleans and object
  keys are not rewritten, so a secret stored as a non-string leaf survives.
- `aws_secret_key` and `generic_api_key` are broad by construction. Narrowing
  `detectors` to what a deployment actually needs keeps false positives from
  turning `block` mode into an outage.
- Bad input fails the load, not the request: an invalid custom regex or an
  unknown config key stops the plugin from registering.

## Observability
Every in-scope evaluation records `mcpg_dlp_evaluate_ms`. Each finding
increments `mcpg_dlp_findings_total` labelled with `detector`, `phase` (`pre` or
`post`) and `action` (`block` or `redact`).

## Build
The `cdylib-export` feature is on by default, so a standalone build already
produces a loadable artifact; a binary that links several plugins together turns
it off so they do not all export `mcpg_plugin_register`:

```bash
cargo build -p mcpg-plugin-security-dlp --features cdylib-export --release   # → target/release/libmcpg_plugin_security_dlp.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin classes, the ABI, and how entries load:
  <https://mcpg.dev/docs/plugins/plugins-and-protocol>
- Full gateway config schema, including `plugins[]`:
  <https://mcpg.dev/docs/reference/configuration>
- Encrypt named fields instead of blocking them:
  `libs/plugins/security/field-crypto`
- Send arguments and results to an external scanning service:
  `libs/plugins/security/guardrails`
