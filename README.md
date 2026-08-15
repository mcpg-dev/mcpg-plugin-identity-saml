# `mcpg-plugin-identity-saml`

SAML 2.0 identity plugin for mcpg (`class: identity_provider`,
`id: dev.mcpg.identity.saml`). Resolves the caller's identity from a SAML
assertion carried in a header by **verifying the IdP's XML signature**,
enforcing signature-wrapping defenses, validating `Conditions` (time +
audience) and `Issuer`, and mapping the `Subject` / attributes to the
identity.

Part of the legacy → MCP bridge suite.

> **System dependency.** Builds against system **libxml2** (`libxml2-dev`) —
> used only for its battle-tested exclusive-C14N (we do **not** hand-roll
> canonicalization). The signature crypto is pure-Rust (`rsa`/`sha2`) — **no
> OpenSSL**. Kept out of the workspace `default-members`; build explicitly
> with `-p mcpg-plugin-identity-saml`.

## How it works

Given the configured header (default `X-SAML-Assertion`) holding a base64
SAML assertion (or a Response wrapping one):

1. **Signature.** The assertion's enveloped XML signature is verified —
   exclusive-C14N (libxml2) + RSA-SHA256/SHA1 (pure-Rust) — against the
   operator-configured **IdP certificate**. The trust anchor is the configured
   cert, **never** the certificate embedded in the (attacker-controllable)
   message. Unknown algorithms/transforms are rejected (fail closed).
2. **Signature-wrapping (XSW) defenses.** The document must contain **exactly
   one** Assertion; its signature must be a **direct child** of that assertion;
   and the verified signature must **cover that assertion's ID**. Identity is
   read only from that one verified assertion.
3. **Conditions.** `NotBefore` / `NotOnOrAfter` (with configurable clock skew)
   and `AudienceRestriction` (must list the configured audience).
4. **Issuer.** Must equal the configured IdP entityID (when set).
5. **Identity.** `Subject/NameID` → `subject_id`; the `role_attribute` →
   `roles`; the `group_attribute` → `groups`; all attributes are projected
   onto `attributes`.

Verification is local and synchronous — no JWKS fetch, no KDC, no outbound
network, no private runtime.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `idp_certificate` | string (required) | — | PEM IdP signing cert — the verification **trust anchor**. A `${env.X}` / `vault://…` / `file://…` reference resolves upstream. Must parse as an RSA cert at load. |
| `idp_entity_id` | string | — | Expected `Issuer`. When set, a mismatched issuer is rejected. |
| `audience` | string | — | This SP's entityID. When set + an `AudienceRestriction` is present, it must list this value. |
| `assertion_header` | string | `X-SAML-Assertion` | Header carrying the base64 assertion. |
| `assertion_scheme` | string | — | Optional scheme to strip (e.g. `SAML` for `Authorization: SAML <b64>`). |
| `role_attribute` | string | `role` | SAML attribute whose values become `roles`. |
| `group_attribute` | string | — | SAML attribute whose values become `groups`. |
| `clock_skew_secs` | int | `120` | Allowed skew on the `Conditions` window. |
| `resolution.trust_level` | `verified`\|`header_asserted` | `verified` | Trust bucket for a verified assertion. |

```yaml
plugins:
  - id: dev.mcpg.identity.saml
    class: identity_provider
    source: { oci: "{{OCI_BASE}}/identity-saml:<ver>" }
    config:
      idp_certificate: "file:///etc/mcpg/idp.crt"   # PEM trust anchor
      idp_entity_id: "https://idp.corp.example.com/saml2"
      audience: "mcpg-gateway"
      role_attribute: "http://schemas.example.com/role"
      group_attribute: "memberOf"
```

A SAML SP front-end (or reverse proxy) terminates the Web SSO POST and places
the assertion in `X-SAML-Assertion`; mcpg verifies it and resolves the
subject + roles into the gateway identity context.

## Security

- **Verify-then-trust.** The signature is checked against the **configured**
  IdP cert. The embedded `X509Certificate` is never trusted.
- **XSW-resistant.** Exactly-one-assertion + direct-child signature +
  signature-covers-the-assertion-ID + identity-from-the-verified-assertion.
- **Strict algorithm allow-list.** exclusive-C14N, enveloped-signature,
  RSA-SHA256 (+ legacy RSA-SHA1), SHA-256 (+ SHA-1). Anything else → reject.
- **No hand-rolled C14N.** Canonicalization is libxml2's; only subtree
  containment (a pointer-ancestor walk) is ours.
- **No OpenSSL.** libxml2 (XML only, no crypto) + pure-Rust RSA.
- **Generic rejections.** Any failure → `Invalid("invalid SAML assertion")`;
  the cause stays in logs.

## Build / test

```bash
cargo build -p mcpg-plugin-identity-saml          # needs libxml2-dev
cargo test  -p mcpg-plugin-identity-saml          # unit tests
# End-to-end against the reference signer (needs openssl + xmlsec1):
cargo test -p mcpg-plugin-identity-saml --features integration-tests
```

The integration tests sign assertions with **xmlsec1** (the reference
implementation) and check that the plugin accepts a valid signature and
**rejects** tampering, the wrong signing key, an expired assertion, and a
signature-wrapping attack (a second forged assertion).

## Scope / deferred

- **Encrypted assertions** (`EncryptedAssertion`) — v1 is signed-plaintext.
- **Response-level signatures** — v1 requires the **Assertion** to be signed
  (the stronger guarantee). Response-only signing is a follow-on.
- **HTTP-Redirect binding / `SAMLResponse` deflate** — v1 takes the assertion
  XML (base64) from a header.
- **DSA/ECDSA signatures** — v1 is RSA.
- A dedicated external security review is recommended before production use.
