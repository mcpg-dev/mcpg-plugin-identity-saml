//! SAML 2.0 assertion validation: signature (via [`crate::dsig`]) plus the
//! security semantics — signature-wrapping (XSW) defenses, conditions
//! (time + audience), issuer, and subject/attribute extraction.

use std::collections::BTreeMap;

use libxml::tree::Node;
use rsa::RsaPublicKey;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::dsig;
use crate::parse_xml;

/// The trustworthy contents of a verified assertion.
pub struct VerifiedAssertion {
    pub subject: String,
    pub issuer: Option<String>,
    /// Attribute `Name` → its values.
    pub attributes: BTreeMap<String, Vec<String>>,
}

/// Validate a SAML assertion (or a Response wrapping exactly one signed
/// assertion). `pubkey` is the operator-configured IdP trust anchor.
#[allow(clippy::too_many_arguments)]
pub fn validate(
    xml: &[u8],
    pubkey: &RsaPublicKey,
    expected_issuer: Option<&str>,
    expected_audience: Option<&str>,
    now: OffsetDateTime,
    clock_skew: Duration,
    allow_unbounded_lifetime: bool,
) -> Result<VerifiedAssertion, String> {
    let doc = parse_xml(xml)?;
    let root = doc.get_root_element().ok_or("empty document")?;

    // XSW defense #1: require EXACTLY ONE Assertion in the whole document. A
    // second (unsigned) assertion is the classic wrapping vector.
    let assertions = root
        .findnodes("//*[local-name()='Assertion' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:assertion']")
        .map_err(|_| "find assertions".to_string())?;
    let assertion = match assertions.as_slice() {
        [a] => a.clone(),
        [] => return Err("no SAML Assertion".into()),
        _ => return Err("multiple Assertions (signature-wrapping defense)".into()),
    };
    let assertion_id = assertion.get_attribute("ID").ok_or("Assertion has no ID")?;

    // XSW defense #2: the signature must be a DIRECT CHILD of the assertion
    // (an assertion-level signature), not a stray signature elsewhere.
    let signature = child(
        &assertion,
        "Signature",
        "http://www.w3.org/2000/09/xmldsig#",
    )
    .ok_or("Assertion is not signed (no direct ds:Signature child)")?;

    // Verify it; require it covers THIS assertion's ID (XSW defense #3 — the
    // signature we checked must protect the assertion we read identity from).
    let covered = dsig::verify(&doc, &signature, pubkey)?;
    if !covered.iter().any(|id| id == &assertion_id) {
        return Err(format!(
            "signature does not cover the Assertion (#{assertion_id})"
        ));
    }

    // Issuer.
    let issuer = child(
        &assertion,
        "Issuer",
        "urn:oasis:names:tc:SAML:2.0:assertion",
    )
    .map(|n| n.get_content().trim().to_owned())
    .filter(|s| !s.is_empty());
    if let Some(expected) = expected_issuer
        && issuer.as_deref() != Some(expected)
    {
        return Err(format!(
            "Issuer mismatch (expected {expected}, got {:?})",
            issuer.as_deref()
        ));
    }

    // Conditions: validity window (with clock skew) + audience restriction.
    if let Some(conditions) = child(
        &assertion,
        "Conditions",
        "urn:oasis:names:tc:SAML:2.0:assertion",
    ) {
        if let Some(nb) = conditions.get_attribute("NotBefore") {
            let nb = parse_instant(&nb)?;
            if now + clock_skew < nb {
                return Err("Assertion not yet valid (Conditions/NotBefore)".into());
            }
        }
        // An assertion is a bearer credential: with no expiry it is valid
        // forever and replayable from any replica, which makes the missing
        // lifetime the weakest link in an otherwise careful implementation.
        match conditions.get_attribute("NotOnOrAfter") {
            Some(na) => {
                let na = parse_instant(&na)?;
                if now - clock_skew >= na {
                    return Err("Assertion expired (Conditions/NotOnOrAfter)".into());
                }
            }
            None if !allow_unbounded_lifetime => {
                return Err("Assertion declares no Conditions/NotOnOrAfter; refusing a \
                            credential that never expires (set \
                            allow_unbounded_assertion_lifetime to accept it)"
                    .into());
            }
            None => {}
        }
        if let Some(expected) = expected_audience {
            let audiences: Vec<String> = conditions
                .findnodes(".//*[local-name()='Audience']")
                .map_err(|_| "find audiences".to_string())?
                .iter()
                .map(|n| n.get_content().trim().to_owned())
                .collect();
            // When an audience is required, the assertion MUST carry an
            // AudienceRestriction that lists us. A missing / empty / non-
            // matching restriction is rejected — otherwise an assertion the
            // IdP minted for a *different* service provider would be accepted
            // here (confused-deputy).
            if !audiences.iter().any(|a| a == expected) {
                return Err(format!(
                    "audience restriction does not include the required audience {expected}"
                ));
            }
        }
    } else if expected_audience.is_some() {
        return Err("Assertion has no Conditions but an audience is required".into());
    } else if !allow_unbounded_lifetime {
        return Err(
            "Assertion carries no Conditions at all, so it declares no validity \
                    window; refusing a credential that never expires (set \
                    allow_unbounded_assertion_lifetime to accept it)"
                .into(),
        );
    }

    // Subject NameID.
    let subject = assertion
        .findnodes(".//*[local-name()='Subject']/*[local-name()='NameID']")
        .map_err(|_| "find subject".to_string())?
        .into_iter()
        .next()
        .map(|n| n.get_content().trim().to_owned())
        .filter(|s| !s.is_empty())
        .ok_or("Assertion has no Subject/NameID")?;

    // Attributes (Name → values).
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for attr in assertion
        .findnodes(".//*[local-name()='AttributeStatement']/*[local-name()='Attribute']")
        .map_err(|_| "find attributes".to_string())?
    {
        let Some(name) = attr.get_attribute("Name") else {
            continue;
        };
        let values: Vec<String> = attr
            .findnodes("./*[local-name()='AttributeValue']")
            .map_err(|_| "find attribute values".to_string())?
            .iter()
            .map(|n| n.get_content().trim().to_owned())
            .collect();
        attributes.entry(name).or_default().extend(values);
    }

    Ok(VerifiedAssertion {
        subject,
        issuer,
        attributes,
    })
}

/// A direct child element by local-name + namespace.
fn child(node: &Node, local: &str, ns: &str) -> Option<Node> {
    node.findnodes(&format!(
        "./*[local-name()='{local}' and namespace-uri()='{ns}']"
    ))
    .ok()
    .and_then(|v| v.into_iter().next())
}

/// Parse a SAML/XSD `dateTime` (RFC3339 / ISO-8601 UTC).
fn parse_instant(s: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(s.trim(), &Rfc3339).map_err(|e| format!("bad dateTime '{s}': {e}"))
}
