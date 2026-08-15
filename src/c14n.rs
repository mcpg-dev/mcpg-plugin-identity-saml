//! Exclusive XML canonicalization (C14N 1.0 exclusive) of a node subtree,
//! delegating to **libxml2** — we do not hand-roll C14N (a subtle bug there is
//! a signature-bypass). The only logic here is a node-visibility predicate
//! (subtree containment), which libxml2 calls while it walks the tree and
//! renders the canonical form (handling attribute + namespace nodes itself).

use std::ffi::CString;
use std::os::raw::{c_int, c_void};

use libxml::bindings::{
    xmlAllocOutputBuffer, xmlBufContent, xmlBufUse, xmlC14NExecute,
    xmlC14NMode_XML_C14N_EXCLUSIVE_1_0, xmlChar, xmlDocPtr, xmlElementType_XML_ELEMENT_NODE,
    xmlNodePtr, xmlOutputBufferClose, xmlOutputBufferFlush,
};

/// Subtree-visibility state for the C14N callback: include nodes under
/// `target`, except those under `exclude` (the enveloped-signature transform).
struct VisCtx {
    target: xmlNodePtr,
    exclude: xmlNodePtr, // may be null
}

/// libxml2 C14N visibility callback. A node is visible iff its containing
/// element is a descendant-or-self of `target` and not of `exclude`.
unsafe extern "C" fn is_visible(
    user_data: *mut c_void,
    node: xmlNodePtr,
    parent: xmlNodePtr,
) -> c_int {
    if user_data.is_null() || node.is_null() {
        return 0;
    }
    // SAFETY: `user_data` is the `&VisCtx` we passed to `xmlC14NExecute`.
    let ctx = unsafe { &*(user_data as *const VisCtx) };
    // Element nodes anchor on themselves; attribute / namespace / text nodes
    // anchor on their owning element (`parent`), since libxml2 passes the
    // element as `parent` for those.
    let is_element = unsafe { (*node).type_ } == xmlElementType_XML_ELEMENT_NODE;
    let mut cur = if is_element {
        node
    } else if !parent.is_null() {
        parent
    } else {
        node
    };
    while !cur.is_null() {
        if cur == ctx.exclude {
            return 0; // inside the excluded (signature) subtree
        }
        if cur == ctx.target {
            return 1; // reached target without passing through exclude
        }
        cur = unsafe { (*cur).parent };
    }
    0 // not under target at all
}

/// Exclusive-C14N the subtree rooted at `target`, excluding the subtree rooted
/// at `exclude` (pass null for none), with the given `InclusiveNamespaces`
/// prefix list. Returns the canonical octets.
///
/// # Safety
///
/// `doc`, `target`, and (if non-null) `exclude` must be valid libxml2 pointers
/// from the same live `Document`/`Node` tree, and must remain alive for the
/// call.
pub unsafe fn canonicalize_exclusive(
    doc: xmlDocPtr,
    target: xmlNodePtr,
    exclude: xmlNodePtr,
    inclusive_prefixes: &[String],
) -> Result<Vec<u8>, String> {
    if doc.is_null() || target.is_null() {
        return Err("canonicalize: null doc/target".into());
    }
    // NULL-terminated `xmlChar**` of inclusive-namespace prefixes (or null).
    let cstrings: Vec<CString> = inclusive_prefixes
        .iter()
        .map(|p| CString::new(p.as_str()).map_err(|e| format!("ns prefix: {e}")))
        .collect::<Result<_, _>>()?;
    let mut ptrs: Vec<*mut xmlChar> = cstrings
        .iter()
        .map(|c| c.as_ptr() as *mut xmlChar)
        .collect();
    ptrs.push(std::ptr::null_mut());
    let ns_arg = if inclusive_prefixes.is_empty() {
        std::ptr::null_mut()
    } else {
        ptrs.as_mut_ptr()
    };

    let ctx = VisCtx { target, exclude };
    // SAFETY: all pointers are valid for the duration of the call; `ctx` and
    // `cstrings`/`ptrs` outlive `xmlC14NExecute`.
    let bytes = unsafe {
        let buf = xmlAllocOutputBuffer(std::ptr::null_mut());
        if buf.is_null() {
            return Err("xmlAllocOutputBuffer failed".into());
        }
        let rc = xmlC14NExecute(
            doc,
            Some(is_visible),
            &ctx as *const VisCtx as *mut c_void,
            xmlC14NMode_XML_C14N_EXCLUSIVE_1_0 as c_int,
            ns_arg,
            0, // with_comments = false
            buf,
        );
        if rc < 0 {
            xmlOutputBufferClose(buf);
            return Err(format!("xmlC14NExecute failed (rc={rc})"));
        }
        xmlOutputBufferFlush(buf);
        let inner = (*buf).buffer;
        let out = if inner.is_null() {
            Vec::new()
        } else {
            let content = xmlBufContent(inner);
            let len = xmlBufUse(inner);
            if content.is_null() || len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(content as *const u8, len).to_vec()
            }
        };
        xmlOutputBufferClose(buf);
        out
    };
    Ok(bytes)
}
