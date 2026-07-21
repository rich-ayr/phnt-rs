//! Verification (spec §5, stage 6; §7 `verify`; acceptance criteria §8).
//!
//! A build is acceptable only if all hold, per `(version × arch)` cell and for
//! the `kernel` feature on `{x86_64, aarch64}`:
//! 1. `ctest` passes (size/offset/signedness/constant vs the real headers);
//! 2. generated `const _: () = assert!(size_of/offset_of == …)` layout checks
//!    compile (rustc's layout == clang's, from `-fdump-record-layouts`);
//! 3. the crate compiles under that cell's features, the full set, and
//!    `--features kernel` (incl. a `#![no_std]` probe);
//! 4. the merge round-trip property (spec §8.4) — implement early as the primary
//!    regression net;
//! 5. gate closure / no-dangling-reference (spec §4b, §8.5).
//!
//! ## Layout parity (check #2) — implemented here
//!
//! [`parse_layouts`] reads clang's `-fdump-record-layouts-complete` dump (captured
//! by the [driver](crate::driver)) into a `tag name → RecordLayout` map, and
//! [`emit_layout_checks`] turns it into a `#[cfg(test)] mod _layout_checks` full of
//! compile-time `const _: () = assert!(size_of/align_of/offset_of == …)` items. The
//! numbers are clang's ground truth, frozen into the generated source: the emitted
//! `ffi` then *self-verifies* under `cargo test` with no clang/SDK present.
//!
//! Correlation is by **tag name only** — clang identifies records by their tag
//! (`struct _FOO`) or, for anonymous ones, `(unnamed at FILE:LINE:COL)`. Emitted
//! records whose names are synthetic (hoisted anon `Parent__anonN`) or come from
//! the SDK `typedef struct {…} T;` idiom (dumped anonymously by clang) therefore
//! get no *direct* check — but they are covered *transitively*: every by-value use
//! sits inside a tag-named parent whose total size and field offsets we do assert.
//! Opaque stubs (`_EPROCESS`, `_IRP`, …) have no complete layout in the TU and so
//! nothing to check; their pointer-sized uses are verified in their parents.
//!
//! TODO(M1): `ctest` wiring (check #1). TODO(M3): the §8.4 round-trip property.
//! TODO(M2/M3): §8.5 closure check. TODO: loc-based correlation to also cover the
//! anon-typedef and hoisted-anon records directly.

use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::ctype;
use crate::ir::Record;

/// The layout of one record as measured by clang, in bytes.
#[derive(Clone, Debug, Default)]
pub struct RecordLayout {
    pub is_union: bool,
    pub size: u64,
    pub align: u64,
    /// Direct (depth-1), *named*, non-bitfield fields → byte offset. Bitfield and
    /// anonymous members are omitted (no stable Rust field to name in `offset_of!`).
    pub fields: BTreeMap<String, u64>,
}

/// `tag name → layout`, e.g. `_UNICODE_STRING → { size: 16, align: 8, … }`.
pub type LayoutMap = BTreeMap<String, RecordLayout>;

/// Parse a clang `-fdump-record-layouts-complete` dump into a name→layout map.
///
/// The dump is a sequence of blocks, each introduced by a
/// `*** Dumping AST Record Layout` marker:
///
/// ```text
/// *** Dumping AST Record Layout
///          0 | struct _UNICODE_STRING
///          0 |   USHORT Length
///          2 |   USHORT MaximumLength
///          8 |   unsigned short * Buffer
///            | [sizeof=16, align=8]
/// ```
///
/// The column before `|` is the byte offset (or `byte:startbit-endbit` for a
/// bitfield); after `|`, indentation encodes depth — `1 + 2·depth` leading spaces,
/// so the header/summary sit at 1 and direct fields at 3. We keep only top-level,
/// tag-named records and their direct scalar fields (see the module docs for why).
pub fn parse_layouts(text: &str) -> LayoutMap {
    let mut map = LayoutMap::new();

    let mut name: Option<String> = None;
    let mut cur = RecordLayout::default();
    let mut expecting_header = false;
    let mut skip = false;

    let flush = |map: &mut LayoutMap, name: &mut Option<String>, cur: &mut RecordLayout| {
        if let Some(n) = name.take() {
            map.insert(n, std::mem::take(cur));
        } else {
            *cur = RecordLayout::default();
        }
    };

    for line in text.lines() {
        if line.contains("*** Dumping AST Record Layout") {
            flush(&mut map, &mut name, &mut cur);
            expecting_header = true;
            skip = false;
            continue;
        }
        let Some(pipe) = line.find('|') else { continue };
        let offset_part = line[..pipe].trim();
        let rest = &line[pipe + 1..];
        let lead = rest.len() - rest.trim_start().len();
        let content = rest.trim_start();

        // Summary line: `[sizeof=N, align=M, …]` (C++ adds dsize/nvsize/nvalign).
        if content.starts_with('[') {
            for tok in content.trim_start_matches('[').trim_end_matches(']').split(',') {
                let tok = tok.trim();
                if let Some(v) = tok.strip_prefix("sizeof=") {
                    cur.size = v.trim().parse().unwrap_or(0);
                } else if let Some(v) = tok.strip_prefix("align=") {
                    cur.align = v.trim().parse().unwrap_or(0);
                }
            }
            continue;
        }

        // Header line: `struct NAME` / `union NAME` / `class NAME`.
        if expecting_header {
            expecting_header = false;
            let (kind, tag) = content.split_once(' ').unwrap_or(("struct", content));
            // Anonymous or nested records are named `X::(unnamed…)` / `(unnamed at …)`;
            // we can only correlate a bare tag to an emitted Rust type.
            if tag.contains("::") || tag.contains("(unnamed") || tag.contains("(anonymous") {
                skip = true;
            } else {
                cur.is_union = kind == "union";
                name = Some(tag.trim().to_string());
            }
            continue;
        }

        // Field line. Only direct (depth-1 ⇒ 3 leading spaces), named, non-bitfield.
        if skip || lead != 3 {
            continue;
        }
        if offset_part.contains(':') {
            continue; // bitfield member (`byte:startbit-endbit`) — no Rust field
        }
        let Ok(off) = offset_part.parse::<u64>() else { continue };
        if let Some(fname) = field_name(content) {
            cur.fields.insert(fname, off);
        }
    }
    flush(&mut map, &mut name, &mut cur);
    map
}

/// Extract the trailing field identifier from a layout field line's content, e.g.
/// `unsigned short * Buffer` → `Buffer`, `CHAR Name[16]` → `Name`. Returns `None`
/// for an anonymous member (`union X::(unnamed at …)`, ends in `)`), where there
/// is no nameable Rust field.
fn field_name(content: &str) -> Option<String> {
    let mut t = content.trim_end();
    // Strip any trailing array subscripts: `Name[16][2]` → `Name`.
    while t.ends_with(']') {
        let Some(i) = t.rfind('[') else { break };
        t = t[..i].trim_end();
    }
    let b = t.as_bytes();
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let end = t.len();
    if end == 0 || !is_ident(b[end - 1]) {
        return None; // ends in `)`/`*`/… → anonymous member
    }
    let mut start = end;
    while start > 0 && is_ident(b[start - 1]) {
        start -= 1;
    }
    // A field line is always `<type> <name>`; a single token means type-only.
    if start == 0 || b[start].is_ascii_digit() {
        return None;
    }
    Some(t[start..end].to_string())
}

/// Records whose faithful Rust layout needs an emitter feature we don't have yet,
/// so we cannot assert their size/offsets. Each is excluded from the checks with a
/// reason and re-enabled automatically once the feature lands (the assertions will
/// then simply pass). Kept tiny and explicit on purpose — it is the honest ledger
/// of what the harness does *not* yet prove, not a place to silence real failures.
///
/// Currently **empty**: the two former entries were fixed — `__ptr32` 4-byte
/// pointers (`ctype`, emitted as `u32`) and per-field `DECLSPEC_CACHEALIGN`
/// (`emit::synth_padded_fields`, explicit padding). Left in place as scaffolding
/// for cases that new cells/arches may surface.
const KNOWN_LAYOUT_DIVERGENT: &[(&str, &str)] = &[];

/// Statistics from a layout-check pass, for the generator's progress report.
#[derive(Clone, Debug, Default)]
pub struct CheckStats {
    /// Emitted (non-anon) records that matched a clang layout by tag name.
    pub matched: usize,
    /// Emitted (non-anon) records with no layout entry (anon-typedef / opaque).
    pub unmatched: usize,
    /// Hoisted-anon records skipped (covered transitively via their parent).
    pub anon_skipped: usize,
    /// Records excluded via [`KNOWN_LAYOUT_DIVERGENT`] (unsupported layout feature).
    pub known_divergent: usize,
    pub size_checks: usize,
    pub offset_checks: usize,
}

/// Emit the `#[cfg(test)] mod _layout_checks { … }` compile-time assertions for
/// every emitted record that clang measured, and report coverage stats.
pub fn emit_layout_checks(
    records: &BTreeMap<String, Record>,
    layouts: &LayoutMap,
) -> (TokenStream, CheckStats) {
    let mut stats = CheckStats::default();
    let mut items: Vec<TokenStream> = Vec::new();

    for (name, rec) in records {
        // Hoisted anon records carry synthetic names clang never emits; their bytes
        // are proven through the enclosing tag-named parent.
        if rec.anon {
            stats.anon_skipped += 1;
            continue;
        }
        if let Some((_, why)) = KNOWN_LAYOUT_DIVERGENT.iter().find(|(n, _)| n == name) {
            stats.known_divergent += 1;
            eprintln!("[phnt-bindgen] layout check skipped for {name}: {why}");
            continue;
        }
        let Some(layout) = layouts.get(name) else {
            stats.unmatched += 1;
            continue;
        };
        stats.matched += 1;

        let ty = format_ident!("{}", ctype::sanitize_ident(name));
        let size = layout.size as usize;
        let align = layout.align as usize;
        let mut asserts: Vec<TokenStream> = Vec::new();
        asserts.push(quote! { assert!(::core::mem::size_of::<#ty>() == #size); });
        asserts.push(quote! { assert!(::core::mem::align_of::<#ty>() == #align); });
        stats.size_checks += 1;

        for f in &rec.fields {
            if f.bitfield_width.is_some() {
                continue; // coalesced into a `_bitfield_N` storage unit — no 1:1 field
            }
            let Some(fname) = &f.name else { continue };
            let Some(off) = layout.fields.get(fname) else { continue };
            let fi = format_ident!("{}", ctype::sanitize_ident(fname));
            let off = *off as usize;
            asserts.push(quote! { assert!(::core::mem::offset_of!(#ty, #fi) == #off); });
            stats.offset_checks += 1;
        }
        items.push(quote! { const _: () = { #(#asserts)* }; });
    }

    let module = quote! {
        /// Compile-time layout parity assertions against clang's record-layout dump
        /// (ground truth). Frozen numbers ⇒ no clang/SDK needed to re-verify; run
        /// with `cargo test`. `cfg(test)` keeps consumer builds free of the checks.
        #[cfg(test)]
        mod _layout_checks {
            #[allow(unused_imports)]
            use super::*;
            #(#items)*
        }
    };
    (module, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
*** Dumping AST Record Layout
         0 | struct _UNICODE_STRING
         0 |   USHORT Length
         2 |   USHORT MaximumLength
         8 |   unsigned short * Buffer
           | [sizeof=16, align=8]

*** Dumping AST Record Layout
         0 | struct Bits
     0:0-0 |   ULONG a
     0:1-3 |   ULONG b
    0:4-31 |   ULONG c
     4:0-3 |   USHORT s
           | [sizeof=8, align=4]

*** Dumping AST Record Layout
         0 | struct WithAnon::(unnamed at foo.c:23:9)
    0:0-15 |   ULONG Lo
           | [sizeof=4, align=4]

*** Dumping AST Record Layout
         0 | struct WithAnon
         0 |   ULONG PackedValue
         4 |   union WithAnon::(unnamed at foo.c:21:5) u
         4 |     ULONG Whole
         8 |   UCHAR tail[4]
           | [sizeof=12, align=4]
";

    #[test]
    fn parses_scalar_record() {
        let m = parse_layouts(SAMPLE);
        let u = m.get("_UNICODE_STRING").expect("record present");
        assert_eq!(u.size, 16);
        assert_eq!(u.align, 8);
        assert_eq!(u.fields.get("Length"), Some(&0));
        assert_eq!(u.fields.get("MaximumLength"), Some(&2));
        assert_eq!(u.fields.get("Buffer"), Some(&8));
    }

    #[test]
    fn bitfield_fields_are_omitted_but_size_kept() {
        let m = parse_layouts(SAMPLE);
        let b = m.get("Bits").expect("record present");
        assert_eq!(b.size, 8);
        assert_eq!(b.align, 4);
        // Bitfield members have no addressable offset → not recorded.
        assert!(b.fields.is_empty());
    }

    #[test]
    fn anon_and_nested_records_are_skipped() {
        let m = parse_layouts(SAMPLE);
        // `WithAnon::(unnamed …)` must not appear under any key.
        assert!(m.keys().all(|k| !k.contains("unnamed") && !k.contains("::")));
    }

    #[test]
    fn direct_fields_only_no_nested_leak() {
        let m = parse_layouts(SAMPLE);
        let w = m.get("WithAnon").expect("record present");
        assert_eq!(w.size, 12);
        // `PackedValue`, `u`, and the array field `tail` are direct; `Whole`
        // (depth-2, inside the anon union) must not leak in.
        assert_eq!(w.fields.get("PackedValue"), Some(&0));
        assert_eq!(w.fields.get("u"), Some(&4));
        assert_eq!(w.fields.get("tail"), Some(&8));
        assert!(!w.fields.contains_key("Whole"));
    }

    #[test]
    fn field_name_extraction() {
        assert_eq!(field_name("unsigned short * Buffer").as_deref(), Some("Buffer"));
        assert_eq!(field_name("CHAR Name[16]").as_deref(), Some("Name"));
        assert_eq!(field_name("ULONG a[2][3]").as_deref(), Some("a"));
        assert_eq!(field_name("union X::(unnamed at f.c:1:1)"), None);
        assert_eq!(field_name("ULONG PackedValue").as_deref(), Some("PackedValue"));
    }
}
