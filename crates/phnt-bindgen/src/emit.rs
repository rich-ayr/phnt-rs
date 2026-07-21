//! Rust emission (spec §5, stage 5; §7 `emit`).
//!
//! Generates with `quote`, formats with `prettyplease` (deterministic, no
//! rustfmt). Emits `core::ffi` types and AST-reported calling conventions so the
//! crate is `no_std`-clean (spec §4c).
//!
//! Types are **raw and self-contained**: starting from the phnt-origin roots,
//! [`closure`] walks named type references to the fixpoint, pulling every
//! transitively-referenced SDK type (`UNICODE_STRING`, `GUID`, `HANDLE`, …) out
//! of the *same* AST via the universe index — no `windows-sys` dependency.
//! Types with no definition in the TU (opaque kernel/GDI handles used only behind
//! pointers, e.g. `_EPROCESS`) become zero-sized opaque stubs.
//!
//! Bitfields follow the "raw storage" model (project decision, 2026-07-21): each
//! run coalesces into storage units of its base integer type — correct size and
//! alignment, no accessors (those belong in `ext`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{Context, Result};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::ctype::{self, CType, Prim};
use crate::ir::{CallingConv, Enum, Function, Module, Record, Typedef};
use crate::universe::Index;

/// The resolved, self-contained set of items to emit for one cell.
#[derive(Default)]
struct Closure {
    records: BTreeMap<String, Record>,
    enums: BTreeMap<String, Enum>,
    typedefs: BTreeMap<String, Typedef>,
    /// Referenced names with no definition in the TU — emitted as opaque stubs.
    opaque: BTreeSet<String>,
}

/// Emit a formatted, self-contained Rust `ffi` source string for `m`.
pub fn emit(m: &Module, idx: &Index) -> Result<String> {
    let closure = compute_closure(m, idx);
    let tokens = generate(m, &closure);
    let file = syn::parse2::<syn::File>(tokens).context("emitted tokens are not valid Rust")?;
    Ok(prettyplease::unparse(&file))
}

// ---------------------------------------------------------------------------
// Closure
// ---------------------------------------------------------------------------

/// Collect the `Named` references of a type (skips resolved `Anon`/primitives).
fn refs_of(ty: &CType, out: &mut Vec<String>) {
    let mut names = Vec::new();
    ty.collect_refs(&mut names);
    for n in names {
        // Anon leaves would look like a path (`...h:line:col`); none should remain.
        if !n.contains(".h:") && !n.contains(".c:") {
            out.push(n.to_string());
        }
    }
}

fn record_refs(r: &Record, out: &mut Vec<String>) {
    for f in &r.fields {
        refs_of(&f.ty, out);
    }
}

/// Seed from the phnt roots, then walk name references to the fixpoint, lowering
/// external SDK types on demand from the universe index.
fn compute_closure(m: &Module, idx: &Index) -> Closure {
    let mut c = Closure::default();
    let mut queue: VecDeque<String> = VecDeque::new();

    // Seed: every phnt-origin record/enum/typedef (records already include the
    // hoisted anon members).
    for r in &m.records {
        if let Some(name) = &r.name {
            c.records.entry(name.clone()).or_insert_with(|| r.clone());
        }
    }
    for e in &m.enums {
        if let Some(name) = &e.name {
            c.enums.entry(name.clone()).or_insert_with(|| e.clone());
        }
    }
    for t in &m.typedefs {
        c.typedefs.entry(t.name.clone()).or_insert_with(|| t.clone());
    }

    // Seed the worklist with every reference from the roots (incl. function sigs).
    let mut seed = Vec::new();
    for r in &m.records {
        record_refs(r, &mut seed);
    }
    for t in &m.typedefs {
        refs_of(&t.ty, &mut seed);
    }
    for e in &m.enums {
        if let Some(u) = &e.underlying {
            refs_of(&ctype::parse(u), &mut seed);
        }
    }
    for f in &m.functions {
        refs_of(&f.ret, &mut seed);
        for p in &f.params {
            refs_of(&p.ty, &mut seed);
        }
    }
    queue.extend(seed);

    while let Some(name) = queue.pop_front() {
        if c.records.contains_key(&name)
            || c.enums.contains_key(&name)
            || c.typedefs.contains_key(&name)
            || c.opaque.contains(&name)
        {
            continue;
        }
        if let Some(node) = idx.rec_by_name.get(name.as_str()) {
            let mut lowered = Vec::new();
            crate::ir::lower_record_node(node, &mut lowered);
            for r in lowered {
                let mut refs = Vec::new();
                record_refs(&r, &mut refs);
                queue.extend(refs);
                if let Some(rn) = &r.name {
                    c.records.entry(rn.clone()).or_insert(r.clone());
                }
            }
        } else if let Some(node) = idx.anon_typedef_rec.get(name.as_str()) {
            // `typedef struct {…} T;` — lower the anonymous struct *as* `T`.
            let mut lowered = Vec::new();
            crate::ir::lower_record(node, name.clone(), String::new(), false, &mut lowered);
            for r in lowered {
                let mut refs = Vec::new();
                record_refs(&r, &mut refs);
                queue.extend(refs);
                if let Some(rn) = &r.name {
                    c.records.entry(rn.clone()).or_insert(r.clone());
                }
            }
        } else if let Some(node) = idx.enum_by_name.get(name.as_str()) {
            if let Some(e) = crate::ir::lower_enum_node(node) {
                c.enums.insert(name.clone(), e);
            }
        } else if let Some(node) = idx.anon_typedef_enum.get(name.as_str()) {
            // `typedef enum {…} T;` — lower the anonymous enum *as* `T`.
            if let Some(mut e) = crate::ir::lower_enum_node(node) {
                e.name = Some(name.clone());
                c.enums.insert(name.clone(), e);
            }
        } else if let Some(node) = idx.typedef_by_name.get(name.as_str()) {
            if let Some(t) = crate::ir::lower_typedef_node(node) {
                // `typedef struct X X;` where the tag `X` has no complete
                // definition in this TU (a version-guarded/forward-declared SDK
                // struct) → emit `X` as an opaque type, not a self-alias that
                // resolves to nothing.
                let self_alias = matches!(&t.ty, CType::Named(n) if *n == t.name);
                if self_alias {
                    c.opaque.insert(name.clone());
                } else {
                    let mut refs = Vec::new();
                    refs_of(&t.ty, &mut refs);
                    queue.extend(refs);
                    c.typedefs.insert(name.clone(), t);
                }
            }
        } else {
            // No definition anywhere in the TU → opaque (kernel/GDI/ETW handles,
            // used only behind pointers).
            c.opaque.insert(name);
        }
    }

    if std::env::var_os("PHNT_DEBUG_CLOSURE").is_some() {
        let probe = "POWER_ACTION_POLICY";
        eprintln!(
            "[closure] records={} enums={} typedefs={} opaque={}",
            c.records.len(),
            c.enums.len(),
            c.typedefs.len(),
            c.opaque.len()
        );
        eprintln!(
            "[closure] {probe}: rec={} td={} opaque={} | idx.rec={} idx.td={} idx.enum={}",
            c.records.contains_key(probe),
            c.typedefs.contains_key(probe),
            c.opaque.contains(probe),
            idx.rec_by_name.contains_key(probe),
            idx.typedef_by_name.contains_key(probe),
            idx.enum_by_name.contains_key(probe),
        );
        eprintln!(
            "[closure] _SYSTEM_POWER_POLICY_ACDC in c.records = {}",
            c.records.contains_key("_SYSTEM_POWER_POLICY_ACDC")
        );
    }

    c
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

fn generate(m: &Module, c: &Closure) -> TokenStream {
    let records = c.records.values().map(|r| emit_record(r, &c.typedefs));
    let enums = c.enums.values().map(emit_enum);
    let typedefs = c.typedefs.values().filter_map(emit_typedef);
    let opaque = c.opaque.iter().map(|n| emit_opaque(n));
    let funcs = emit_functions(&m.functions);

    quote! {
        //! Auto-generated by `phnt-bindgen`. DO NOT EDIT.
        //!
        //! Raw, self-contained `#[repr(C)]` FFI for the phnt native Windows headers.
        #![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]

        #(#opaque)*
        #(#typedefs)*
        #(#enums)*
        #(#records)*
        #funcs
    }
}

fn ident(name: &str) -> proc_macro2::Ident {
    format_ident!("{}", ctype::sanitize_ident(name))
}

// --- records ---------------------------------------------------------------

fn emit_record(r: &Record, typedefs: &BTreeMap<String, Typedef>) -> TokenStream {
    let name = ident(r.name.as_deref().unwrap_or("_anon"));
    let body = emit_fields(&r.fields, typedefs);
    if r.is_union {
        quote! {
            #[repr(C)]
            #[derive(Copy, Clone)]
            pub union #name { #body }
        }
    } else {
        quote! {
            #[repr(C)]
            #[derive(Copy, Clone)]
            pub struct #name { #body }
        }
    }
}

fn emit_fields(fields: &[crate::ir::Field], typedefs: &BTreeMap<String, Typedef>) -> TokenStream {
    let mut out: Vec<TokenStream> = Vec::new();
    let mut anon_ctr = 0usize;
    let mut bitfield_ctr = 0usize;
    let mut i = 0;
    while i < fields.len() {
        if fields[i].bitfield_width.is_some() {
            let start = i;
            while i < fields.len() && fields[i].bitfield_width.is_some() {
                i += 1;
            }
            emit_bitfield_units(&fields[start..i], typedefs, &mut bitfield_ctr, &mut out);
        } else {
            let f = &fields[i];
            let fname = match &f.name {
                Some(n) => ident(n),
                None => {
                    anon_ctr += 1;
                    format_ident!("__anon{}", anon_ctr)
                }
            };
            let ty = f.ty.to_rust();
            out.push(quote! { pub #fname: #ty });
            i += 1;
        }
    }
    quote! { #(#out),* }
}

/// Coalesce a run of consecutive bitfields into raw storage units of their base
/// integer type (MSVC packing: a new unit starts when the base type changes, the
/// unit fills, or a zero-width field forces a boundary). Correct size/alignment;
/// no accessors (deferred to `ext`).
fn emit_bitfield_units(
    run: &[crate::ir::Field],
    typedefs: &BTreeMap<String, Typedef>,
    ctr: &mut usize,
    out: &mut Vec<TokenStream>,
) {
    let mut units: Vec<Prim> = Vec::new();
    let mut cur: Option<Prim> = None;
    let mut used_bits: u32 = 0;
    for f in run {
        let width: u32 = f.bitfield_width.as_deref().and_then(|w| w.parse().ok()).unwrap_or(0);
        let prim = resolve_prim(&f.ty, typedefs).unwrap_or(Prim::ULong);
        let unit_bits = prim_size(prim) as u32 * 8;
        if width == 0 {
            // Zero-width bitfield: flush current unit, force the next to a boundary.
            if let Some(p) = cur.take() {
                units.push(p);
            }
            used_bits = 0;
            continue;
        }
        match cur {
            Some(p) if p == prim && used_bits + width <= unit_bits => used_bits += width,
            _ => {
                if let Some(p) = cur.take() {
                    units.push(p);
                }
                cur = Some(prim);
                used_bits = width;
            }
        }
    }
    if let Some(p) = cur {
        units.push(p);
    }
    for p in units {
        *ctr += 1;
        let fname = format_ident!("_bitfield_{}", ctr);
        let ty = p.to_rust();
        out.push(quote! { pub #fname: #ty });
    }
}

/// Follow `Named` typedefs to the underlying integer primitive (for bitfield unit
/// sizing). Falls back to a small table of well-known integer typedefs.
fn resolve_prim(ty: &CType, typedefs: &BTreeMap<String, Typedef>) -> Option<Prim> {
    let mut cur = ty.clone();
    for _ in 0..32 {
        match cur {
            CType::Prim(p) => return Some(p),
            CType::Named(n) => {
                if let Some(p) = well_known_prim(&n) {
                    return Some(p);
                }
                cur = typedefs.get(&n)?.ty.clone();
            }
            _ => return None,
        }
    }
    None
}

fn well_known_prim(n: &str) -> Option<Prim> {
    Some(match n {
        "ULONG" | "DWORD" | "UINT" | "ULONG32" | "DWORD32" => Prim::ULong,
        "LONG" | "INT" | "INT32" | "LONG32" | "BOOL" | "NTSTATUS" | "HRESULT" => Prim::Long,
        "USHORT" | "WORD" | "UINT16" | "WCHAR" => Prim::UShort,
        "SHORT" | "INT16" => Prim::Short,
        "UCHAR" | "BYTE" | "BOOLEAN" | "UINT8" => Prim::UChar,
        "CHAR" | "CCHAR" | "INT8" => Prim::Char,
        "ULONGLONG" | "ULONG64" | "DWORD64" | "DWORDLONG" | "UINT64" | "QWORD" | "SIZE_T"
        | "ULONG_PTR" | "DWORD_PTR" => Prim::UInt64,
        "LONGLONG" | "LONG64" | "INT64" | "LONG_PTR" | "SSIZE_T" => Prim::Int64,
        _ => return None,
    })
}

fn prim_size(p: Prim) -> usize {
    use Prim::*;
    match p {
        Char | SChar | UChar => 1,
        Short | UShort | WcharT => 2,
        Int | UInt | Long | ULong | Float => 4,
        LongLong | ULongLong | Int64 | UInt64 | Double => 8,
    }
}

// --- typedefs --------------------------------------------------------------

fn emit_typedef(t: &Typedef) -> Option<TokenStream> {
    let name = ident(&t.name);
    let ty = t.ty.to_rust();
    // Skip a self-referential alias (`type X = X;`), which clang can produce for
    // `typedef struct X X;` where the tag and typedef share a name.
    if ctype::sanitize_ident(&t.name) == ty.to_string().trim() {
        return None;
    }
    Some(quote! { pub type #name = #ty; })
}

// --- enums (constified) ----------------------------------------------------

fn emit_enum(e: &Enum) -> TokenStream {
    // Resolve constant values (implicit = previous + 1), then pick an underlying
    // integer type that fits them (or the fixed underlying type if declared).
    let mut vals: Vec<(String, i128)> = Vec::new();
    let mut next: i128 = 0;
    for k in &e.constants {
        let v = k
            .value
            .as_deref()
            .and_then(|s| s.trim().parse::<i128>().ok())
            .unwrap_or(next);
        vals.push((k.name.clone(), v));
        next = v + 1;
    }

    let repr = enum_repr(e, &vals);
    let repr_tokens = repr.to_rust();

    let consts = vals.iter().map(|(n, v)| {
        let cn = ident(n);
        let lit = proc_macro2::Literal::i128_unsuffixed(*v);
        quote! { pub const #cn: #repr_tokens = #lit; }
    });

    match &e.name {
        Some(tag) => {
            let tn = ident(tag);
            quote! {
                pub type #tn = #repr_tokens;
                #(#consts)*
            }
        }
        // Anonymous enum: no type alias, constants stand alone at `repr` type.
        None => quote! { #(#consts)* },
    }
}

fn enum_repr(e: &Enum, vals: &[(String, i128)]) -> Prim {
    if let Some(u) = &e.underlying {
        if let Some(p) = resolve_prim(&ctype::parse(u), &BTreeMap::new()) {
            return p;
        }
    }
    // Infer a fitting type (C enums are `int` unless values don't fit).
    let (mut min, mut max) = (0i128, 0i128);
    for (_, v) in vals {
        min = min.min(*v);
        max = max.max(*v);
    }
    if min >= i32::MIN as i128 && max <= i32::MAX as i128 {
        Prim::Int
    } else if min >= 0 && max <= u32::MAX as i128 {
        Prim::ULong
    } else if min >= i64::MIN as i128 && max <= i64::MAX as i128 {
        Prim::Int64
    } else {
        Prim::UInt64
    }
}

// --- opaque ----------------------------------------------------------------

fn emit_opaque(name: &str) -> TokenStream {
    let n = ident(name);
    // Incomplete type: used only behind pointers (kernel/GDI/ETW handles).
    quote! {
        #[repr(C)]
        #[derive(Copy, Clone)]
        pub struct #n {
            _opaque: [u8; 0],
        }
    }
}

// --- functions -------------------------------------------------------------

fn emit_functions(functions: &[Function]) -> TokenStream {
    // Group by ABI: stdcall → "system" (stdcall on x86, C on x64 — exactly the
    // NTAPI contract); everything else → "C".
    // Dedup by name: a few functions are declared under more than one header
    // (e.g. `NtUserSetFocus`); duplicate `pub fn` names in an extern block are a
    // hard error. First declaration wins.
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut by_abi: BTreeMap<&str, Vec<&Function>> = BTreeMap::new();
    for f in functions {
        if !seen.insert(f.name.as_str()) {
            continue;
        }
        let abi = match f.calling_conv {
            CallingConv::Stdcall => "system",
            _ => "C",
        };
        by_abi.entry(abi).or_default().push(f);
    }
    let blocks = by_abi.into_iter().map(|(abi, mut fns)| {
        fns.sort_by(|a, b| a.name.cmp(&b.name));
        let decls = fns.iter().map(|f| emit_fn_decl(f));
        let abi_lit = proc_macro2::Literal::string(abi);
        quote! {
            unsafe extern #abi_lit {
                #(#decls)*
            }
        }
    });
    quote! { #(#blocks)* }
}

fn emit_fn_decl(f: &Function) -> TokenStream {
    let name = ident(&f.name);
    let params = f.params.iter().enumerate().map(|(i, p)| {
        let pn = match &p.name {
            Some(n) if !n.is_empty() => ident(n),
            _ => format_ident!("param{}", i),
        };
        let ty = p.ty.to_rust();
        quote! { #pn: #ty }
    });
    let ret = match &f.ret {
        CType::Void => quote! {},
        other => {
            let t = other.to_rust();
            quote! { -> #t }
        }
    };
    quote! { pub fn #name(#(#params),*) #ret; }
}
