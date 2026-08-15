//! Operator-supplied configuration schema for `dev.mcpg.identity.saml`.

use serde::Deserialize;
use thiserror::Error;

use crate::dsig;

/// Top-level plugin config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    /// PEM-encoded IdP signing certificate — the verification **trust
    /// anchor**. Signatures are verified against this key, never the
    /// certificate embedded in the (attacker-controllable) message. A
    /// `${env.X}` / `vault://…` / `file://…` reference is resolved upstream.
    pub idp_certificate: String,

    /// Expected `Issuer` (IdP entityID). When set, an assertion from a
    /// different issuer is rejected.
    #[serde(default)]
    pub idp_entity_id: Option<String>,

    /// Expected audience (this SP's entityID). When set and the assertion
    /// carries an `AudienceRestriction`, it must list this value.
    #[serde(default)]
    pub audience: Option<String>,

    /// Accept an assertion that declares no `Conditions/NotOnOrAfter`.
    ///
    /// A SAML assertion is a bearer credential, so without an expiry it is
    /// valid forever and replayable from any replica. Production MUST leave
    /// this false; it exists for the rare IdP that genuinely omits the
    /// attribute, mirroring the `allow_any_audience` escape hatch the
    /// jwt/oidc siblings use.
    #[serde(default)]
    pub allow_unbounded_assertion_lifetime: bool,

    /// Header carrying the base64 SAML assertion/response (default
    /// `X-SAML-Assertion`).
    #[serde(default = "default_assertion_header")]
    pub assertion_header: String,

    /// Optional scheme prefix to strip from the header value (e.g. `SAML` for
    /// `Authorization: SAML <b64>`). Omit when the whole header value is the
    /// base64 payload.
    #[serde(default)]
    pub assertion_scheme: Option<String>,

    /// SAML attribute whose values become `roles` (default `role`).
    #[serde(default = "default_role_attribute")]
    pub role_attribute: String,

    /// SAML attribute whose values become `groups`.
    #[serde(default)]
    pub group_attribute: Option<String>,

    /// Clock skew (seconds) allowed on the `Conditions` validity window.
    #[serde(default = "default_clock_skew")]
    pub clock_skew_secs: u64,

    /// Trust level + provider label applied to resolved identities.
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

/// Trust posture applied to verified callers.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    /// A verified IdP signature is cryptographic proof of the assertion's
    /// authenticity, so `"verified"` is the natural default; operators on
    /// weaker contracts downgrade to `"header_asserted"`.
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
    /// `auth_provider` label on the resolved `PluginIdentity`.
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

fn default_assertion_header() -> String {
    "X-SAML-Assertion".into()
}
fn default_role_attribute() -> String {
    "role".into()
}
fn default_clock_skew() -> u64 {
    120
}
fn default_trust_level() -> String {
    "verified".into()
}
fn default_auth_provider_label() -> String {
    "saml".into()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid identity.saml config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("identity.saml: idp_certificate must not be empty")]
    EmptyCertificate,
    #[error("identity.saml: idp_certificate is not a valid RSA certificate: {0}")]
    BadCertificate(String),
    #[error("identity.saml: assertion_header must not be empty")]
    EmptyHeader,
    #[error("identity.saml: invalid trust_level `{0}` (allowed: verified | header_asserted)")]
    InvalidTrustLevel(String),
}

impl SamlConfig {
    /// Parse + validate from JSON (also confirms the IdP certificate parses).
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.idp_certificate.trim().is_empty() {
            return Err(ConfigError::EmptyCertificate);
        }
        dsig::rsa_pubkey_from_cert_pem(&self.idp_certificate)
            .map_err(ConfigError::BadCertificate)?;
        if self.assertion_header.trim().is_empty() {
            return Err(ConfigError::EmptyHeader);
        }
        match self.resolution.trust_level.as_str() {
            "verified" | "header_asserted" => {}
            other => return Err(ConfigError::InvalidTrustLevel(other.into())),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A SAML assertion is a bearer credential, so accepting one with no
    /// expiry means accepting a credential that never expires. The escape
    /// hatch must be opt-in, never the default.
    #[test]
    fn unbounded_assertion_lifetime_is_refused_by_default() {
        let cfg: SamlConfig =
            serde_json::from_value(json!({ "idp_certificate": "-----BEGIN CERTIFICATE-----" }))
                .expect("minimal config parses");
        assert!(
            !cfg.allow_unbounded_assertion_lifetime,
            "an assertion with no NotOnOrAfter must be refused unless explicitly opted in"
        );
    }

    #[test]
    fn rejects_bad_certificate() {
        let cfg = json!({ "idp_certificate": "not a cert" }).to_string();
        assert!(matches!(
            SamlConfig::parse(&cfg).unwrap_err(),
            ConfigError::BadCertificate(_)
        ));
    }

    #[test]
    fn rejects_empty_certificate() {
        let cfg = json!({ "idp_certificate": "" }).to_string();
        assert!(matches!(
            SamlConfig::parse(&cfg).unwrap_err(),
            ConfigError::EmptyCertificate
        ));
    }
}
