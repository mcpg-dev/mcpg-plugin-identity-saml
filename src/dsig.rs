//! XML Digital Signature verification (the security-critical core), restricted
//! to the standard SAML signing profile and **fail-closed** on anything else.
//!
//! Supported: exclusive-C14N, enveloped-signature transform, RSA-SHA256 (and
//! legacy RSA-SHA1), SHA-256 (and SHA-1) digests. Any other algorithm /
//! transform is rejected. Canonicalization is libxml2's (see [`crate::c14n`]);
//! the digest + RSA verification are pure-Rust.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use libxml::tree::{Document, Node};
use libxml::xpath::Context;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::der::{DecodePem, Encode};

use crate::c14n::canonicalize_exclusive;

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const C14N_EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA1_URI: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

/// Parse an operator-configured IdP certificate (PEM) → its RSA public key.
/// This is the verification **trust anchor** — never the cert embedded in the
/// (attacker-controllable) message.
pub fn rsa_pubkey_from_cert_pem(pem: &str) -> Result<RsaPublicKey, String> {
    let cert = Certificate::from_pem(pem.as_bytes())
        .map_err(|e| format!("parse IdP certificate PEM: {e}"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| format!("encode certificate SPKI: {e}"))?;
    RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| format!("certificate is not an RSA key: {e}"))
}

fn one(node: &Node, xpath: &str) -> Result<Node, String> {
    node.at_xpath(xpath, &[("ds", DS)])
        .map_err(|_| format!("xpath {xpath}"))?
        .ok_or_else(|| format!("missing element: {xpath}"))
}

fn all(node: &Node, xpath: &str) -> Result<Vec<Node>, String> {
    let mut ctx = Context::from_node(node).map_err(|_| "xpath context".to_string())?;
    ctx.register_namespace("ds", DS)
        .map_err(|_| "register ns".to_string())?;
    ctx.findnodes(xpath, Some(node))
        .map_err(|_| format!("findnodes {xpath}"))
}

fn algorithm(node: &Node, child: &str) -> Result<String, String> {
    Ok(one(node, child)?
        .get_attribute("Algorithm")
        .unwrap_or_default())
}

fn digest(uri: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    match uri {
        SHA256_URI => Ok(Sha256::digest(data).to_vec()),
        SHA1_URI => Ok(Sha1::digest(data).to_vec()),
        other => Err(format!("unsupported DigestMethod: {other}")),
    }
}

/// Inclusive-namespace PrefixList from an `<…><ec:InclusiveNamespaces
/// PrefixList="a b"/></…>` child of a c14n method/transform, if present.
fn inclusive_prefixes(method: &Node) -> Vec<String> {
    method
        .findnodes("./*[local-name()='InclusiveNamespaces']")
        .ok()
        .and_then(|v| v.into_iter().next())
        .and_then(|n| n.get_attribute("PrefixList"))
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// A reference URI like `#_id` must point to a syntactically-safe id (also
/// prevents XPath injection when we dereference it).
fn safe_id(uri: &str) -> Result<String, String> {
    let id = uri
        .strip_prefix('#')
        .ok_or_else(|| format!("only same-document Reference URIs are supported, got '{uri}'"))?;
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
    {
        return Err(format!("unsafe Reference id '{id}'"));
    }
    Ok(id.to_owned())
}

/// Verify the `signature` element against `public_key`. On success returns the
/// list of element IDs the signature covers (for the caller's
/// signature-wrapping defense). Any failure → `Err` (fail closed).
pub fn verify(
    doc: &Document,
    signature: &Node,
    public_key: &RsaPublicKey,
) -> Result<Vec<String>, String> {
    let signed_info = one(signature, "./ds:SignedInfo")?;

    // Canonicalization + signature algorithms — strict allow-list.
    let c14n_alg = algorithm(&signed_info, "./ds:CanonicalizationMethod")?;
    if c14n_alg != C14N_EXC {
        return Err(format!("unsupported CanonicalizationMethod: {c14n_alg}"));
    }
    let sig_alg = algorithm(&signed_info, "./ds:SignatureMethod")?;
    let sig_is_sha256 = match sig_alg.as_str() {
        RSA_SHA256 => true,
        RSA_SHA1 => false,
        other => return Err(format!("unsupported SignatureMethod: {other}")),
    };

    // Verify every Reference's digest.
    let references = all(&signed_info, "./ds:Reference")?;
    if references.is_empty() {
        return Err("SignedInfo has no Reference".into());
    }
    let mut covered_ids = Vec::new();
    for reference in &references {
        let uri = reference.get_attribute("URI").unwrap_or_default();
        let id = safe_id(&uri)?;

        // Transforms: must be a subset of {enveloped, exclusive-c14n} and
        // include exclusive-c14n. The enveloped transform = exclude the
        // Signature subtree from the referenced element's canonical form.
        let transforms = all(reference, "./ds:Transforms/ds:Transform")?;
        let mut saw_c14n = false;
        let mut c14n_transform: Option<Node> = None;
        for t in &transforms {
            match t.get_attribute("Algorithm").unwrap_or_default().as_str() {
                ENVELOPED => {}
                C14N_EXC => {
                    saw_c14n = true;
                    c14n_transform = Some(t.clone());
                }
                other => return Err(format!("unsupported Transform: {other}")),
            }
        }
        if !saw_c14n {
            return Err("Reference is missing the exclusive-c14n transform".into());
        }

        // Dereference the referenced element by id.
        let target = doc
            .get_root_element()
            .and_then(|root| {
                root.findnodes(&format!("//*[@ID='{id}']"))
                    .ok()
                    .and_then(|v| v.into_iter().next())
            })
            .ok_or_else(|| format!("Reference target #{id} not found"))?;

        let prefixes = c14n_transform
            .as_ref()
            .map(inclusive_prefixes)
            .unwrap_or_default();
        // SAFETY: all pointers come from the live `doc` / its nodes, which
        // outlive this call.
        let canon = unsafe {
            canonicalize_exclusive(
                doc.doc_ptr(),
                target.node_ptr(),
                signature.node_ptr(), // enveloped: exclude the signature subtree
                &prefixes,
            )?
        };

        let digest_alg = algorithm(reference, "./ds:DigestMethod")?;
        let computed = digest(&digest_alg, &canon)?;
        let declared = B64
            .decode(one(reference, "./ds:DigestValue")?.get_content().trim())
            .map_err(|e| format!("DigestValue base64: {e}"))?;
        if computed != declared {
            return Err(format!("digest mismatch for Reference #{id}"));
        }
        covered_ids.push(id);
    }

    // Verify the signature over the canonicalized SignedInfo.
    let si_prefixes = inclusive_prefixes(&one(&signed_info, "./ds:CanonicalizationMethod")?);
    // SAFETY: pointers come from the live `doc` / `signed_info`.
    let si_canon = unsafe {
        canonicalize_exclusive(
            doc.doc_ptr(),
            signed_info.node_ptr(),
            std::ptr::null_mut(),
            &si_prefixes,
        )?
    };
    let sig_value = B64
        .decode(
            one(signature, "./ds:SignatureValue")?
                .get_content()
                .split_whitespace()
                .collect::<String>(),
        )
        .map_err(|e| format!("SignatureValue base64: {e}"))?;

    let verified = if sig_is_sha256 {
        public_key.verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(&si_canon),
            &sig_value,
        )
    } else {
        public_key.verify(
            Pkcs1v15Sign::new::<Sha1>(),
            &Sha1::digest(&si_canon),
            &sig_value,
        )
    };
    verified.map_err(|e| format!("signature verification failed: {e}"))?;

    Ok(covered_ids)
}
