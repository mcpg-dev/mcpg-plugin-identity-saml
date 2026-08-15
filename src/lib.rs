//! `dev.mcpg.identity.saml` — SAML 2.0 identity plugin.
//!
//! Resolves caller identity from a SAML assertion carried in a configured
//! header (default `X-SAML-Assertion`, base64). The IdP **signature is
//! verified** (exclusive-C14N via libxml2 + pure-Rust RSA — see [`dsig`]),
//! signature-wrapping (XSW) defenses are enforced, `Conditions` (time +
//! audience) and `Issuer` are validated, and the `Subject`/attributes become
//! the identity.
//!
//! # Trust model
//!
//! The trust anchor is the operator-configured IdP certificate — never the
//! certificate embedded in the (attacker-controllable) message. A verified
//! signature is `resolution.trust_level: "verified"` (default).
//!
//! # System dependency
//!
//! Uses **libxml2** for DOM parse + exclusive-C14N (the signed-element
//! canonicalizer). Native glibc + macOS builds link the system libxml2
//! (`libxml2-dev`); kept out of `default-members`. Cross targets
//! (arm64-gnu / musl / windows) link a STATICALLY-vendored libxml2 built from
//! the pinned source under `vendor/` by `tools/release/build-saml-cross.sh`,
//! so those artifacts carry libxml2 internally and need no runtime libxml2.
//! No OpenSSL.

pub mod c14n;
pub mod config;
pub mod dsig;
pub mod saml;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use libxml::parser::Parser;
use libxml::tree::Document;
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use rsa::RsaPublicKey;
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use tracing::{debug, info_span, warn};

pub use config::{ConfigError, ResolutionConfig, SamlConfig};

const PLUGIN_ID: &str = "dev.mcpg.identity.saml";

/// Parse XML into a libxml `Document` under a hardened parser policy.
///
/// The SAML response is attacker-influenced (it rides in on the request), so
/// the parser forbids the network (`no_net`) and refuses error-recovery
/// (`recover: false`) — a malformed or ambiguous document is rejected rather
/// than best-effort reconstructed before signature verification. The `libxml`
/// crate exposes no entity-substitution / DTD-load flag, so `XML_PARSE_NOENT`
/// / `XML_PARSE_DTDLOAD` are never set and external-entity XXE is off by
/// construction; `no_net` closes the residual SSRF surface and `huge` stays
/// off so libxml2's built-in entity-expansion limits apply.
pub fn parse_xml(xml: &[u8]) -> Result<Document, String> {
    let options = libxml::parser::ParserOptions {
        recover: false,
        no_net: true,
        ..Default::default()
    };
    Parser::default()
        .parse_string_with_options(xml, options)
        .map_err(|e| format!("parse XML: {e}"))
}

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!("mcpg_identity_saml_resolutions_total", "outcome" => outcome).increment(1);
    metrics::histogram!("mcpg_identity_saml_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            roles = identity.roles.len(),
            "saml identity resolved"
        ),
        IdentityResolution::None => debug!("saml identity: no assertion header — fall through"),
        IdentityResolution::Invalid { reason } => {
            warn!(reason = %reason, "saml identity: rejected")
        }
    }
}

pub struct SamlIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    pubkey: RsaPublicKey,
    idp_entity_id: Option<String>,
    audience: Option<String>,
    assertion_header: String,
    assertion_scheme: Option<String>,
    role_attribute: String,
    group_attribute: Option<String>,
    clock_skew: Duration,
    allow_unbounded_assertion_lifetime: bool,
    resolution: ResolutionConfig,
}

impl SamlIdentityPlugin {
    /// SDK macro factory: parse config + the IdP certificate. Panics on bad
    /// config — same stance as the oidc/kerberos siblings.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = SamlConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(plugin_id = PLUGIN_ID, error = %err, "saml identity: config parse failed; refusing to register");
            panic!(
                "saml identity config parse failed: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load."
            )
        });
        let pubkey = dsig::rsa_pubkey_from_cert_pem(&cfg.idp_certificate)
            .unwrap_or_else(|e| panic!("saml identity: IdP certificate: {e}"));
        tracing::info!(plugin_id = PLUGIN_ID, header = %cfg.assertion_header, "saml identity: configured");
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "SAML 2.0 Identity Resolver".into(),
                    plugin_class: PluginClass::IdentityProvider,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                pubkey,
                idp_entity_id: cfg.idp_entity_id,
                audience: cfg.audience,
                assertion_header: cfg.assertion_header,
                assertion_scheme: cfg.assertion_scheme,
                role_attribute: cfg.role_attribute,
                group_attribute: cfg.group_attribute,
                clock_skew: Duration::seconds(cfg.clock_skew_secs as i64),
                allow_unbounded_assertion_lifetime: cfg.allow_unbounded_assertion_lifetime,
                resolution: cfg.resolution,
            }),
        }
    }

    fn build_identity(&self, va: saml::VerifiedAssertion) -> PluginIdentity {
        let inner = &self.inner;
        let roles = va
            .attributes
            .get(&inner.role_attribute)
            .cloned()
            .unwrap_or_default();
        let groups = inner
            .group_attribute
            .as_ref()
            .and_then(|g| va.attributes.get(g))
            .cloned()
            .unwrap_or_default();
        // Project the first value of each SAML attribute onto the identity.
        let mut attributes = BTreeMap::new();
        for (k, vals) in &va.attributes {
            if let Some(first) = vals.first() {
                attributes.insert(k.clone(), first.clone());
            }
        }
        PluginIdentity {
            kind: inner.resolution.trust_level.clone(),
            trust_level: inner.resolution.trust_level.clone(),
            subject_id: Some(va.subject),
            auth_provider: Some(inner.resolution.auth_provider_label.clone()),
            issuer: va.issuer.or_else(|| inner.idp_entity_id.clone()),
            roles,
            groups,
            scopes: Vec::new(),
            attributes,
        }
    }

    fn resolve(&self, headers: &[(String, String)]) -> IdentityResolution {
        let inner = &self.inner;
        let Some(raw) = lookup_header(headers, &inner.assertion_header) else {
            return IdentityResolution::None;
        };
        let payload = match &inner.assertion_scheme {
            Some(scheme) => match strip_scheme(raw, scheme) {
                Some(p) => p,
                None => return IdentityResolution::None,
            },
            None => raw,
        };
        // SAML POST base64 may be line-wrapped — strip whitespace.
        let compact: String = payload.split_whitespace().collect();
        if compact.is_empty() {
            return IdentityResolution::None;
        }
        let xml = match BASE64_STANDARD.decode(compact.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                return IdentityResolution::Invalid {
                    reason: "malformed SAML assertion (base64)".into(),
                };
            }
        };
        match saml::validate(
            &xml,
            &inner.pubkey,
            inner.idp_entity_id.as_deref(),
            inner.audience.as_deref(),
            OffsetDateTime::now_utc(),
            inner.clock_skew,
            inner.allow_unbounded_assertion_lifetime,
        ) {
            Ok(va) => IdentityResolution::Resolved {
                identity: self.build_identity(va),
            },
            Err(detail) => {
                warn!(detail = %detail, "saml identity: assertion rejected");
                IdentityResolution::Invalid {
                    reason: "invalid SAML assertion".into(),
                }
            }
        }
    }
}

fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(target).then_some(value.as_str()))
}

/// Strip a case-insensitive `<scheme> ` prefix.
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let n = scheme.len();
    let head: String = value.chars().take(n).collect();
    if head.len() != n || !head.eq_ignore_ascii_case(scheme) {
        return None;
    }
    value[n..].strip_prefix(' ')
}

#[async_trait]
impl IdentityProviderPlugin for SamlIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_saml_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = self.resolve(headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

impl SyncIdentityResolver for SamlIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_saml_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = self.resolve(headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {

    plugin_id: "dev.mcpg.identity.saml",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    // Verification is local against the configured IdP cert — no outbound.
    capabilities: &[],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: SamlIdentityPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> SamlIdentityPlugin {
                SamlIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_scheme_case_insensitive() {
        assert_eq!(strip_scheme("SAML abc", "SAML"), Some("abc"));
        assert_eq!(strip_scheme("saml abc", "SAML"), Some("abc"));
        assert_eq!(strip_scheme("Bearer abc", "SAML"), None);
    }

    #[test]
    fn lookup_header_is_case_insensitive() {
        let h = vec![("X-Saml-Assertion".into(), "v".into())];
        assert_eq!(lookup_header(&h, "x-saml-assertion"), Some("v"));
        assert_eq!(lookup_header(&h, "authorization"), None);
    }
}
