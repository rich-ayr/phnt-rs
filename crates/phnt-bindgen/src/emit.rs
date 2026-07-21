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
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::ctype::{self, CType, Prim};
use crate::ir::{CallingConv, Enum, Function, Module, Record, Typedef};
use crate::matrix::Cell;
use crate::merge::{CapturedAxis, Key, Kind, Occ, derive_gate};
use crate::universe::Index;
use crate::verify::{CheckStats, LayoutMap};

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
///
/// When `layouts` is `Some`, a `#[cfg(test)] mod _layout_checks` of compile-time
/// `size_of`/`align_of`/`offset_of` assertions against clang's record-layout dump
/// is appended (spec §8 check #2); the coverage stats are logged to stderr.
pub fn emit(
    m: &Module,
    idx: &Index,
    layouts: Option<&crate::verify::LayoutMap>,
    append_checks: bool,
    ptr_bytes: u64,
) -> Result<String> {
    let closure = compute_closure(m, idx);
    let mut tokens = generate(m, &closure, layouts, ptr_bytes);
    if let (Some(layouts), true) = (layouts, append_checks) {
        let (checks, stats) = crate::verify::emit_layout_checks(&closure.records, layouts);
        eprintln!(
            "[phnt-bindgen] layout parity: {} records matched, {} unmatched (anon-typedef/opaque), \
             {} hoisted-anon skipped, {} known-divergent; {} size+align, {} offset asserts",
            stats.matched,
            stats.unmatched,
            stats.anon_skipped,
            stats.known_divergent,
            stats.size_checks,
            stats.offset_checks,
        );
        tokens = quote! { #tokens #checks };
    }
    let file = syn::parse2::<syn::File>(tokens).context("emitted tokens are not valid Rust")?;
    Ok(prettyplease::unparse(&file))
}

// ---------------------------------------------------------------------------
// Merged (multi-cell) emission — spec §5 stage 4/5, §8.4/§8.5.
//
// Consumes the `(version × arch × surface)` matrix instead of one `Module`, folds
// every cell's *closure* (roots + on-demand SDK types) into one gated universe,
// and stamps each item's `#[cfg(...)]` from its occurrence set (`merge::Gate`).
//
// **Why merge closures, not roots:** the closure of cell C already contains every
// type an emitted item in C references. So if item A occurs in C, every type A
// uses also occurs in C — hence each referenced type's gate is *at least as loose*
// as A's, and the gate-closure invariant `cfg(A) ⇒ cfg(T)` (§4b(2)) holds **by
// construction**. `check_gate_closure` verifies this rather than having to repair
// it (it should never fire); a violation would signal a closure/merge bug.
// ---------------------------------------------------------------------------

/// One matrix cell's on-disk inputs for [`emit_merged`]. Files are parsed lazily
/// inside the fold so only one ~300 MB AST is resident at a time.
pub struct CellSpec {
    pub cell: Cell,
    pub ast_path: PathBuf,
    /// Optional clang record-layout dump for this cell (drives `#[repr]` selection
    /// *and* the gated parity assertions).
    pub layout_path: Option<PathBuf>,
    /// Target pointer width in bytes (4 on x86, 8 on x64/arm64).
    pub ptr_bytes: u64,
}

/// The accumulated, rendered-once-per-variant state folded across all cells.
/// Everything is keyed by [`Key`] `(kind, name, definition_hash)` so a same-named
/// item whose shape changed between versions splits into gate-disjoint variants.
#[derive(Default)]
struct FoldState {
    occs: BTreeMap<Key, BTreeSet<Occ>>,
    refs: BTreeMap<Key, BTreeSet<String>>,
    /// Records need per-cell context (`#[repr]`, padding, layout), so they are
    /// rendered in the first cell a variant is seen in; enums/typedefs/functions
    /// render context-free from any occurrence.
    rec_tokens: BTreeMap<Key, TokenStream>,
    rec_checks: BTreeMap<Key, TokenStream>,
    enum_tokens: BTreeMap<Key, TokenStream>,
    typedef_tokens: BTreeMap<Key, TokenStream>,
    /// `(abi, decl)` — abi groups the extern block, decl is gated inside it.
    fn_tokens: BTreeMap<Key, (&'static str, TokenStream)>,
    opaque_occs: BTreeMap<String, BTreeSet<Occ>>,
    stats: CheckStats,
}

/// Emit one self-contained, `#[cfg]`-gated Rust `ffi` source folding every cell in
/// `cells` (which must share an arch; the version axis is what gates). When
/// `append_checks`, a per-variant-gated `#[cfg(test)] mod _layout_checks` is added.
///
/// The §8.4 round-trip (`filter(merged, cell) == cell`) and §8.5 gate closure are
/// both enforced here: closure membership is what the occurrence sets encode, and
/// [`check_gate_closure`] fails generation if any edge escapes its referent's gate.
pub fn emit_merged(cells: &[CellSpec], append_checks: bool) -> Result<String> {
    if cells.is_empty() {
        bail!("emit_merged: no cells");
    }
    let mut st = FoldState::default();

    for spec in cells {
        fold_cell(spec, append_checks, &mut st)?;
    }

    // Captured extent, over every variant's occurrences (records guarantee every
    // cell is represented; opaque folds in too for completeness).
    let mut axis = CapturedAxis::default();
    let extend_axis = |set: &BTreeSet<Occ>, axis: &mut CapturedAxis| {
        for &o in set {
            axis.versions.insert(o.ordinal);
            axis.arches.insert(o.arch);
            axis.surfaces.insert(o.surface);
            axis.cells.insert(o);
        }
    };
    for set in st.occs.values() {
        extend_axis(set, &mut axis);
    }
    for set in st.opaque_occs.values() {
        extend_axis(set, &mut axis);
    }

    // Occurrence union by name over the *defined* kinds (record/enum/typedef) —
    // needed both to suppress opaque stubs where a real definition exists and for
    // the gate-closure check.
    let defined_by_name = defined_occs_by_name(&st.occs);

    check_round_trip(&st, &axis)?;
    check_gate_closure(&st, &defined_by_name)?;

    // A gate → `#[cfg(...)]` predicate for an occurrence set.
    let pred_of = |set: &BTreeSet<Occ>| derive_gate(set, &axis).cfg_predicate(&axis);

    // --- assemble each section (opaque, typedefs, enums, records, funcs) --------
    let opaque = assemble_opaque(&st, &defined_by_name, &axis);

    let typedefs = st
        .typedef_tokens
        .iter()
        .map(|(k, t)| stamp_cfg(&pred_of(&st.occs[k]), t.clone()))
        .collect::<Vec<_>>();
    let enums = st
        .enum_tokens
        .iter()
        .map(|(k, e)| stamp_cfg(&pred_of(&st.occs[k]), e.clone()))
        .collect::<Vec<_>>();
    let records = st
        .rec_tokens
        .iter()
        .map(|(k, r)| stamp_cfg(&pred_of(&st.occs[k]), r.clone()))
        .collect::<Vec<_>>();
    let funcs = assemble_functions(&st, &pred_of);

    let checks = if append_checks {
        let items = st
            .rec_checks
            .iter()
            .map(|(k, c)| stamp_cfg(&pred_of(&st.occs[k]), c.clone()))
            .collect::<Vec<_>>();
        eprintln!(
            "[phnt-bindgen] merged layout parity: {} records matched, {} unmatched, {} anon skipped, \
             {} known-divergent; {} size+align, {} offset asserts (gated across {} versions)",
            st.stats.matched,
            st.stats.unmatched,
            st.stats.anon_skipped,
            st.stats.known_divergent,
            st.stats.size_checks,
            st.stats.offset_checks,
            axis.versions.len(),
        );
        crate::verify::wrap_layout_checks(items)
    } else {
        quote!()
    };

    eprintln!(
        "[phnt-bindgen] merged: {} record variants, {} enums, {} typedefs, {} fns, {} opaque; \
         versions {:?}",
        st.rec_tokens.len(),
        st.enum_tokens.len(),
        st.typedef_tokens.len(),
        st.fn_tokens.len(),
        opaque.len(),
        axis.versions,
    );

    let tokens = quote! {
        //! Auto-generated by `phnt-bindgen`. DO NOT EDIT.
        //!
        //! Raw, self-contained `#[repr(C)]` FFI for the phnt native Windows headers,
        //! merged across the version matrix with `#[cfg(feature = "winNN")]` gates.
        #![allow(non_camel_case_types, non_snake_case, non_upper_case_globals, dead_code)]

        #(#opaque)*
        #(#typedefs)*
        #(#enums)*
        #(#records)*
        #funcs
        #checks
    };

    let file = syn::parse2::<syn::File>(tokens).context("merged tokens are not valid Rust")?;
    Ok(prettyplease::unparse(&file))
}

/// Parse, lower, index and close one cell, then render/record every closure item
/// into `st`. The heavy AST is dropped when this returns (only rendered tokens and
/// occurrence coordinates are retained).
fn fold_cell(spec: &CellSpec, append_checks: bool, st: &mut FoldState) -> Result<()> {
    eprintln!("[phnt-bindgen] merge cell {} ← {}", spec.cell, spec.ast_path.display());
    let node = crate::ir::parse_ast(&spec.ast_path)?;
    let module = crate::ir::lower(&node);
    let idx = crate::universe::build_index(&node);

    let layouts: Option<LayoutMap> = match &spec.layout_path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading layout dump {}", p.display()))?;
            Some(crate::verify::parse_layouts(&text))
        }
        None => None,
    };
    let empty = LayoutMap::new();
    let lay = layouts.as_ref().unwrap_or(&empty);

    let closure = compute_closure(&module, &idx);
    let occ = Occ {
        ordinal: spec.cell.version.ordinal,
        arch: spec.cell.arch,
        surface: spec.cell.surface,
    };

    let enum_align: BTreeMap<String, u64> = closure
        .enums
        .values()
        .filter_map(|e| e.name.clone().map(|n| (n, prim_size(enum_repr_of(e)) as u64)))
        .collect();
    let cx = AlignCtx {
        layouts: lay,
        records: &closure.records,
        enum_align: &enum_align,
        typedefs: &closure.typedefs,
        ptr_bytes: spec.ptr_bytes,
    };
    let reprs = compute_reprs(&closure.records, &cx);

    let mut refbuf: Vec<String> = Vec::new();
    let sink = |st: &mut FoldState, key: &Key, buf: &mut Vec<String>| {
        st.refs.entry(key.clone()).or_default().extend(buf.drain(..));
    };

    for (name, r) in &closure.records {
        let key = Key { kind: Kind::Record, name: name.clone(), def_hash: r.definition_hash() };
        st.occs.entry(key.clone()).or_default().insert(occ);
        record_refs(r, &mut refbuf);
        sink(st, &key, &mut refbuf);
        if !st.rec_tokens.contains_key(&key) {
            let repr = reprs.get(name).copied().unwrap_or(Repr::C);
            st.rec_tokens.insert(key.clone(), emit_record(r, repr, &cx));
            if append_checks
                && let Some(chk) = crate::verify::record_check(name, r, lay, &mut st.stats)
            {
                st.rec_checks.insert(key.clone(), chk);
            }
        }
    }
    for e in closure.enums.values() {
        let name = e.name.clone().unwrap_or_default();
        let key = Key { kind: Kind::Enum, name, def_hash: e.definition_hash() };
        st.occs.entry(key.clone()).or_default().insert(occ);
        if let Some(u) = &e.underlying {
            refs_of(&ctype::parse(u), &mut refbuf);
            sink(st, &key, &mut refbuf);
        }
        st.enum_tokens.entry(key).or_insert_with(|| emit_enum(e));
    }
    for t in closure.typedefs.values() {
        let key = Key { kind: Kind::Typedef, name: t.name.clone(), def_hash: t.definition_hash() };
        st.occs.entry(key.clone()).or_default().insert(occ);
        refs_of(&t.ty, &mut refbuf);
        sink(st, &key, &mut refbuf);
        if !st.typedef_tokens.contains_key(&key)
            && let Some(tok) = emit_typedef(t)
        {
            st.typedef_tokens.insert(key, tok);
        }
    }
    // Dedup functions by name within the cell (first decl wins), matching the
    // single-cell extern-block emitter — two `pub fn X` in one config is an error.
    let mut seen_fn: BTreeSet<&str> = BTreeSet::new();
    for f in &module.functions {
        if !seen_fn.insert(f.name.as_str()) {
            continue;
        }
        let key = Key { kind: Kind::Function, name: f.name.clone(), def_hash: f.definition_hash() };
        st.occs.entry(key.clone()).or_default().insert(occ);
        refs_of(&f.ret, &mut refbuf);
        for p in &f.params {
            refs_of(&p.ty, &mut refbuf);
        }
        sink(st, &key, &mut refbuf);
        let abi = match f.calling_conv {
            CallingConv::Stdcall => "system",
            _ => "C",
        };
        st.fn_tokens.entry(key).or_insert_with(|| (abi, emit_fn_decl(f)));
    }
    for name in &closure.opaque {
        st.opaque_occs.entry(name.clone()).or_default().insert(occ);
    }
    Ok(())
}

/// Occurrence union by tag name over the *defined* kinds (record/enum/typedef) —
/// the cells a given name is a real, emitted type in (any shape variant).
fn defined_occs_by_name(occs: &BTreeMap<Key, BTreeSet<Occ>>) -> BTreeMap<String, BTreeSet<Occ>> {
    let mut out: BTreeMap<String, BTreeSet<Occ>> = BTreeMap::new();
    for (k, set) in occs {
        if matches!(k.kind, Kind::Record | Kind::Enum | Kind::Typedef) {
            out.entry(k.name.clone()).or_default().extend(set.iter().copied());
        }
    }
    out
}

/// Build the opaque-stub items. An opaque name is emitted only for the cells where
/// no real definition of that name exists (`opaque_occs − defined_occs`); a name
/// opaque in every cell it appears (the common kernel-handle case) stays a single
/// unconditional stub, while one that is opaque in some configs and defined in
/// others emits both, on gate-disjoint `#[cfg]`s.
fn assemble_opaque(
    st: &FoldState,
    defined_by_name: &BTreeMap<String, BTreeSet<Occ>>,
    axis: &CapturedAxis,
) -> Vec<TokenStream> {
    let mut out = Vec::new();
    for (name, opaque_occ) in &st.opaque_occs {
        let remaining: BTreeSet<Occ> = match defined_by_name.get(name) {
            Some(def) => opaque_occ.difference(def).copied().collect(),
            None => opaque_occ.clone(),
        };
        if remaining.is_empty() {
            continue; // a real definition covers every cell this name appears in
        }
        let pred = derive_gate(&remaining, axis).cfg_predicate(axis);
        out.push(stamp_cfg(&pred, emit_opaque(name)));
    }
    out
}

/// Group the gated function decls into `unsafe extern "abi"` blocks (spec §4c: the
/// AST-reported calling convention picks `"system"` vs `"C"`). Each decl carries
/// its own `#[cfg]`, so an extern block may be empty under some feature set.
fn assemble_functions(
    st: &FoldState,
    pred_of: &impl Fn(&BTreeSet<Occ>) -> Option<String>,
) -> TokenStream {
    let mut by_abi: BTreeMap<&str, Vec<TokenStream>> = BTreeMap::new();
    for (key, (abi, decl)) in &st.fn_tokens {
        let gated = stamp_cfg(&pred_of(&st.occs[key]), decl.clone());
        by_abi.entry(abi).or_default().push(gated);
    }
    let blocks = by_abi.into_iter().map(|(abi, decls)| {
        let abi_lit = proc_macro2::Literal::string(abi);
        quote! {
            unsafe extern #abi_lit {
                #(#decls)*
            }
        }
    });
    quote! { #(#blocks)* }
}

/// Prefix a `#[cfg(pred)]` onto **each top-level item** in `group` (an enum expands
/// to a type alias plus N consts, so a single leading attribute would gate only the
/// first). `None` ⇒ unconditional, returned verbatim (and without a re-parse — the
/// overwhelming majority of items are shared across all versions).
fn stamp_cfg(pred: &Option<String>, group: TokenStream) -> TokenStream {
    let Some(p) = pred else { return group };
    let cfg_toks: TokenStream = p.parse().expect("cfg predicate is valid tokens");
    let file = syn::parse2::<syn::File>(group).expect("emitted group is valid items");
    let items = file.items.into_iter().map(|it| quote! { #[cfg(#cfg_toks)] #it });
    quote! { #(#items)* }
}

/// Round-trip verification on real captured data (spec §8.4 — the primary
/// regression net). For every captured cell, the compact per-variant gate must
/// admit **exactly** the variants that occurred in that cell: `derive_gate(occs)`
/// reproduces `occs` on the captured axis. An admits-but-didn't-occur mismatch is
/// a phantom (a version gap or arch×version entanglement, spec §9) that the emitted
/// `#[cfg]` would silently include; fail generation rather than ship it. (The
/// synthetic version of this property lives in `merge`'s unit tests; this runs it
/// against the actual merged universe.)
fn check_round_trip(st: &FoldState, axis: &CapturedAxis) -> Result<()> {
    let mut phantoms: Vec<String> = Vec::new();
    for (key, occ_set) in &st.occs {
        let gate = derive_gate(occ_set, axis);
        for &cell in &axis.cells {
            if gate.enables(cell) != occ_set.contains(&cell) {
                phantoms.push(format!(
                    "{:?} {} gate {}s cell {:?} but occurrence set disagrees",
                    key.kind,
                    key.name,
                    if gate.enables(cell) { "admit" } else { "exclude" },
                    cell,
                ));
                break;
            }
        }
    }
    if !phantoms.is_empty() {
        let shown = phantoms.iter().take(10).cloned().collect::<Vec<_>>().join("\n  ");
        bail!(
            "§8.4 round-trip failed — {} variant(s) with a gate that misrepresents their \
             occurrences:\n  {}",
            phantoms.len(),
            shown
        );
    }
    Ok(())
}

/// Gate-closure verification (spec §4b(2)/§8.5). For every emitted item variant and
/// every named type it references, the referent must exist in *every* cell the item
/// occurs in (a real definition or an opaque stub; primitives are unconditional).
/// Closure-level merging makes this hold by construction; a violation is a bug, so
/// this fails generation with the offending edge rather than emitting a dangling
/// reference (the `ntzwapi.h`-class failure §4b describes).
fn check_gate_closure(
    st: &FoldState,
    defined_by_name: &BTreeMap<String, BTreeSet<Occ>>,
) -> Result<()> {
    let mut violations: Vec<String> = Vec::new();
    for (key, refs) in &st.refs {
        let item_occ = &st.occs[key];
        for t in refs {
            if well_known_prim(t).is_some() {
                continue; // rendered inline as a concrete primitive — always present
            }
            let mut avail: BTreeSet<Occ> = BTreeSet::new();
            if let Some(d) = defined_by_name.get(t) {
                avail.extend(d.iter().copied());
            }
            if let Some(o) = st.opaque_occs.get(t) {
                avail.extend(o.iter().copied());
            }
            if avail.is_empty() {
                continue; // not a named emitted type (inline prim / void) — skip
            }
            let missing: Vec<Occ> = item_occ.difference(&avail).copied().collect();
            if !missing.is_empty() {
                violations.push(format!(
                    "{:?} {} references `{t}` absent in {} of its cells (e.g. {:?})",
                    key.kind,
                    key.name,
                    missing.len(),
                    missing[0],
                ));
            }
        }
    }
    if !violations.is_empty() {
        let shown = violations.iter().take(10).cloned().collect::<Vec<_>>().join("\n  ");
        bail!(
            "gate closure violated (§4b(2)) — {} edge(s):\n  {}",
            violations.len(),
            shown
        );
    }
    Ok(())
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

fn generate(
    m: &Module,
    c: &Closure,
    layouts: Option<&crate::verify::LayoutMap>,
    ptr_bytes: u64,
) -> TokenStream {
    // A name→alignment table for records (clang-measured) and enums (repr width),
    // used to decide each record's `#[repr]` (plain / `align(N)` / `packed(N)`).
    let empty = crate::verify::LayoutMap::new();
    let layouts = layouts.unwrap_or(&empty);
    let enum_align: BTreeMap<String, u64> = c
        .enums
        .values()
        .filter_map(|e| e.name.clone().map(|n| (n, prim_size(enum_repr_of(e)) as u64)))
        .collect();

    let cx = AlignCtx {
        layouts,
        records: &c.records,
        enum_align: &enum_align,
        typedefs: &c.typedefs,
        ptr_bytes,
    };
    let reprs = compute_reprs(&c.records, &cx);
    let records = c
        .records
        .values()
        .map(|r| emit_record(r, reprs[r.name.as_deref().unwrap_or("_anon")], &cx));
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

/// How a record's `#[repr(...)]` must deviate from plain `#[repr(C)]` to match
/// clang's measured layout (packed / over-aligned; see [`record_repr`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Repr {
    /// Natural C layout — rustc's `#[repr(C)]` already matches clang.
    C,
    /// `__declspec(align(N))` / over-aligned: raise the struct alignment to `N`.
    Align(u64),
    /// `#pragma pack(N)`: cap field alignment at `N` (tighter offsets, no padding).
    Packed(u64),
}

impl Repr {
    fn attr(self) -> TokenStream {
        match self {
            Repr::C => quote! { #[repr(C)] },
            Repr::Align(n) => {
                let n = proc_macro2::Literal::u64_unsuffixed(n);
                quote! { #[repr(C, align(#n))] }
            }
            // `packed` and `packed(1)` are equivalent; prefer the shorter form.
            Repr::Packed(1) => quote! { #[repr(C, packed)] },
            Repr::Packed(n) => {
                let n = proc_macro2::Literal::u64_unsuffixed(n);
                quote! { #[repr(C, packed(#n))] }
            }
        }
    }
}

/// Render an item's raw Doxygen doc string (captured by `ir::extract_doc`) to
/// rustdoc `#[doc = …]` attributes via `doxygen_bindgen::transform`. One attr per
/// line so prettyplease renders them as `///` comments. Whitespace-only → nothing;
/// a transform error falls back to the raw text so no documentation is lost.
fn doc_attrs(doc: &Option<String>) -> TokenStream {
    let Some(raw) = doc.as_deref() else { return quote!() };
    if raw.trim().is_empty() {
        return quote!();
    }
    let rendered = doxygen_bindgen::transform(raw).unwrap_or_else(|_| raw.to_string());
    if rendered.trim().is_empty() {
        return quote!();
    }
    let attrs = rendered.lines().map(|line| {
        let text = format!(" {}", line.trim_end());
        quote! { #[doc = #text] }
    });
    quote! { #(#attrs)* }
}

fn emit_record(r: &Record, repr: Repr, cx: &AlignCtx) -> TokenStream {
    let name_str = r.name.as_deref().unwrap_or("_anon");
    let name = ident(name_str);
    // Structs with per-field over-alignment (e.g. `DECLSPEC_CACHEALIGN`) need
    // explicit padding to reach clang's offsets — Rust can't align a single field.
    // For everything else this returns `None` and we emit fields verbatim.
    let body = cx
        .layouts
        .get(name_str)
        .filter(|_| !r.is_union)
        .and_then(|l| synth_padded_fields(r, l, cx))
        .unwrap_or_else(|| emit_fields(&r.fields, cx.typedefs));
    let attr = repr.attr();
    let doc = doc_attrs(&r.doc);
    if r.is_union {
        quote! {
            #doc
            #attr
            #[derive(Copy, Clone)]
            pub union #name { #body }
        }
    } else {
        quote! {
            #doc
            #attr
            #[derive(Copy, Clone)]
            pub struct #name { #body }
        }
    }
}

/// Bundle of the closure tables an alignment query needs to resolve a name, plus
/// the target's pointer width (bytes) — the one arch-dependent quantity in the
/// size/alignment model (4 on x86, 8 on x86_64/aarch64). A native pointer's Rust
/// size *and* alignment both equal this; `__ptr32` is always 4.
struct AlignCtx<'a> {
    layouts: &'a crate::verify::LayoutMap,
    records: &'a BTreeMap<String, Record>,
    enum_align: &'a BTreeMap<String, u64>,
    typedefs: &'a BTreeMap<String, Typedef>,
    ptr_bytes: u64,
}

/// The Rust alignment a field type contributes, i.e. the alignment of that type
/// **as we emit it**. Records get clang's measured alignment when known
/// (`layouts`), otherwise their natural alignment computed recursively (hoisted
/// anon members live only in the closure, never in the dump); enums use their
/// repr width; unresolved names emit as opaque `[u8; 0]`, whose alignment is 1.
///
/// Because we always emit `packed(clang.align)` for a packed record — provably
/// equivalent to the original `#pragma pack` for *any* field set — this value only
/// needs to be accurate enough to separate the packed case (`clang.align < nat`)
/// from the over-aligned case (`clang.align > nat`).
fn field_align(ty: &CType, cx: &AlignCtx, depth: u32) -> u64 {
    if depth > 32 {
        return cx.ptr_bytes; // defensive: cap pathological recursion
    }
    match ty {
        CType::Prim(p) => prim_size(*p) as u64, // scalars self-align on win64
        CType::Bool => 1,
        CType::Pointer { ptr32: true, .. } => 4, // WoW64 4-byte pointer ⇒ `u32`
        CType::Pointer { .. } | CType::FnPtr(_) => cx.ptr_bytes,
        CType::Array { inner, .. } => field_align(inner, cx, depth + 1),
        CType::Named(n) => {
            if let Some(rl) = cx.layouts.get(n) {
                return rl.align.max(1);
            }
            if let Some(a) = cx.enum_align.get(n) {
                return *a;
            }
            if let Some(p) = well_known_prim(n) {
                return prim_size(p) as u64;
            }
            if let Some(r) = cx.records.get(n) {
                return natural_align(r, cx, depth + 1);
            }
            if let Some(td) = cx.typedefs.get(n) {
                return field_align(&td.ty, cx, depth + 1);
            }
            1 // opaque / unresolved ⇒ emitted as `[u8; 0]`
        }
        CType::Void | CType::Anon(_) | CType::Unknown(_) => 1,
    }
}

/// The size in bytes a field type occupies, resolved the same way as
/// [`field_align`] but using clang's measured record *sizes*. `None` if any leaf
/// can't be sized exactly (opaque, anon-not-in-dump, unknown) — the caller then
/// declines to synthesize padding for that record rather than risk a wrong offset.
fn field_size(ty: &CType, cx: &AlignCtx, depth: u32) -> Option<u64> {
    if depth > 32 {
        return None;
    }
    Some(match ty {
        CType::Prim(p) => prim_size(*p) as u64,
        CType::Bool => 1,
        CType::Pointer { ptr32: true, .. } => 4, // WoW64 `u32`
        CType::Pointer { .. } | CType::FnPtr(_) => cx.ptr_bytes,
        CType::Array { len, inner } => (*len as u64).checked_mul(field_size(inner, cx, depth + 1)?)?,
        CType::Named(n) => {
            if let Some(rl) = cx.layouts.get(n) {
                rl.size
            } else if let Some(a) = cx.enum_align.get(n) {
                *a // an enum's size == its repr width (== its alignment)
            } else if let Some(p) = well_known_prim(n) {
                prim_size(p) as u64
            } else {
                // Follow a typedef alias; `?` bails (unsizeable: opaque /
                // hoisted-anon record not present in the dump).
                field_size(&cx.typedefs.get(n)?.ty, cx, depth + 1)?
            }
        }
        CType::Void | CType::Anon(_) | CType::Unknown(_) => return None,
    })
}

fn round_up(pos: u64, align: u64) -> u64 {
    pos.div_ceil(align.max(1)) * align.max(1)
}

/// Reproduce clang's layout for a record with per-*field* over-alignment (e.g.
/// `DECLSPEC_CACHEALIGN`, which forces a field to a cache-line boundary) by
/// inserting explicit `[u8; N]` padding — Rust cannot align an individual struct
/// field. Padding is emitted **only** where clang's field offset exceeds the
/// natural offset rustc would already produce (`off > round_up(pos, field_align)`);
/// a purely naturally-aligned struct therefore triggers nothing and is emitted
/// verbatim (returns `None`), leaving the other ~2300 records byte-identical.
///
/// The struct's own `#[repr(C, align(N))]` (chosen by [`record_repr`] from the
/// same over-alignment) supplies the final alignment and tail rounding; this only
/// fixes the *inter-field* offsets. Declines (`None`) for unions, bitfield members,
/// unnamed/undumped fields, or any field it can't size exactly.
fn synth_padded_fields(
    r: &Record,
    layout: &crate::verify::RecordLayout,
    cx: &AlignCtx,
) -> Option<TokenStream> {
    let mut items: Vec<TokenStream> = Vec::new();
    let mut pos: u64 = 0;
    let mut pad_ctr = 0usize;
    let mut needs = false;

    let pad = |items: &mut Vec<TokenStream>, ctr: &mut usize, bytes: u64| {
        *ctr += 1;
        let pn = format_ident!("__pad_{}", *ctr);
        let n = bytes as usize;
        items.push(quote! { pub #pn: [u8; #n] });
    };

    for f in &r.fields {
        if f.bitfield_width.is_some() {
            return None; // bitfield offset model is out of scope here
        }
        let name = f.name.as_deref()?;
        let &off = layout.fields.get(name)?;
        let size = field_size(&f.ty, cx, 0)?;
        let align = field_align(&f.ty, cx, 0);
        if off < round_up(pos, align) {
            return None; // clang placed it *below* the natural offset — inconsistent
        }
        if off > round_up(pos, align) {
            // Over-aligned: fill everything up to `off` explicitly (it is already
            // `align`-aligned, so rustc adds no padding of its own before the field).
            pad(&mut items, &mut pad_ctr, off - pos);
            needs = true;
        }
        let fname = ident(name);
        let ty = f.ty.to_rust();
        items.push(quote! { pub #fname: #ty });
        pos = off + size;
    }

    if !needs {
        return None; // no super-natural gap ⇒ let the verbatim path handle it
    }
    if layout.size > pos {
        pad(&mut items, &mut pad_ctr, layout.size - pos);
    }
    Some(quote! { #(#items),* })
}

/// The natural (unpacked) alignment of a record: the max alignment of its fields.
/// A bitfield contributes its base integer type's alignment.
fn natural_align(r: &Record, cx: &AlignCtx, depth: u32) -> u64 {
    let mut nat: u64 = 1;
    for f in &r.fields {
        let fa = if f.bitfield_width.is_some() {
            resolve_prim(&f.ty, cx.typedefs).map(|p| prim_size(p) as u64).unwrap_or(1)
        } else {
            field_align(&f.ty, cx, depth)
        };
        nat = nat.max(fa);
    }
    nat
}

/// Choose the `#[repr]` for `r` that reproduces clang's measured layout.
///
/// The AST does not carry the numeric `#pragma pack` / `__declspec(align)` value
/// (verified: no `alignment` key in the JSON), so we derive it from the layout
/// dump. Let `nat` be rustc's natural alignment (the max field alignment). clang's
/// final alignment is `min(pack, nat)` for a packed record and `max(declspec, nat)`
/// for an over-aligned one, so:
/// - `clang.align > nat` ⇒ over-aligned ⇒ `align(clang.align)` (offsets unchanged);
/// - `clang.align < nat` ⇒ packed ⇒ `packed(clang.align)` — capping field align at
///   `clang.align` == `min(pack, nat)` yields exactly `pack`'s effect, since every
///   field align is ≤ `nat`.
///
/// Records with no dump entry (anon / anon-typedef) keep plain `#[repr(C)]`; the
/// parity assertions catch anything this misjudges.
fn record_repr(r: &Record, cx: &AlignCtx) -> Repr {
    let Some(rl) = r.name.as_deref().and_then(|n| cx.layouts.get(n)) else {
        return Repr::C; // no ground truth (anon / anon-typedef) ⇒ keep natural
    };
    let ca = rl.align.max(1);
    let nat = natural_align(r, cx, 0);
    if ca > nat {
        Repr::Align(ca)
    } else if ca < nat {
        Repr::Packed(ca)
    } else {
        Repr::C
    }
}

/// Compute every record's `#[repr]`. A first pass sets each record from clang's
/// measured layout ([`record_repr`]); hoisted-anon records have no dump entry so
/// they start at `Repr::C`. A `#pragma pack` is lexically inherited by nested anon
/// members, so a second pass propagates each packed record's `packed(N)` onto the
/// hoisted-anon records it embeds *by value* — otherwise the anon keeps its natural
/// internal padding and inflates the packed parent's size (e.g. `_AFD_ADDRESS`).
/// The propagation runs to a fixpoint for anon-in-anon nesting, taking the tightest
/// (smallest) `N` when an anon is reached from more than one parent.
fn compute_reprs(records: &BTreeMap<String, Record>, cx: &AlignCtx) -> BTreeMap<String, Repr> {
    let mut reprs: BTreeMap<String, Repr> = records
        .iter()
        .map(|(n, r)| (n.clone(), record_repr(r, cx)))
        .collect();

    loop {
        let mut updates: Vec<(String, u64)> = Vec::new();
        for (name, r) in records {
            let Repr::Packed(n) = reprs[name] else { continue };
            for f in &r.fields {
                let mut anons = Vec::new();
                anon_member_names(&f.ty, records, &mut anons);
                for m in anons {
                    updates.push((m, n));
                }
            }
        }
        let mut changed = false;
        for (m, n) in updates {
            let tighter = match reprs.get(&m) {
                Some(Repr::Packed(k)) => n < *k,
                _ => true,
            };
            if tighter {
                reprs.insert(m, Repr::Packed(n));
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    reprs
}

/// Names of the hoisted-anon records a type embeds **by value** (directly or
/// through an array — a pointer/fnptr does not embed its target).
fn anon_member_names(ty: &CType, records: &BTreeMap<String, Record>, out: &mut Vec<String>) {
    match ty {
        CType::Named(n) => {
            if records.get(n).is_some_and(|r| r.anon) {
                out.push(n.clone());
            }
        }
        CType::Array { inner, .. } => anon_member_names(inner, records, out),
        _ => {}
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

/// The base integer `Prim` for a small set of **fixed-width** Windows integer
/// typedefs, used to size bitfield storage units and field alignment when the
/// typedef isn't otherwise resolvable.
///
/// Deliberately excludes the *pointer-sized* integers (`ULONG_PTR`, `LONG_PTR`,
/// `SIZE_T`, `SSIZE_T`, `DWORD_PTR`, `INT_PTR`, `UINT_PTR`): those are 4 bytes on
/// x86 and 8 on x64/arm64, so hardcoding them here mis-sized them on x86 (wrong
/// bitfield storage width, wrong `#[repr]`). They resolve instead through the
/// arch-specific typedef table (from that cell's AST), which is always correct.
fn well_known_prim(n: &str) -> Option<Prim> {
    Some(match n {
        "ULONG" | "DWORD" | "UINT" | "ULONG32" | "DWORD32" => Prim::ULong,
        "LONG" | "INT" | "INT32" | "LONG32" | "BOOL" | "NTSTATUS" | "HRESULT" => Prim::Long,
        "USHORT" | "WORD" | "UINT16" | "WCHAR" => Prim::UShort,
        "SHORT" | "INT16" => Prim::Short,
        "UCHAR" | "BYTE" | "BOOLEAN" | "UINT8" => Prim::UChar,
        "CHAR" | "CCHAR" | "INT8" => Prim::Char,
        "ULONGLONG" | "ULONG64" | "DWORD64" | "DWORDLONG" | "UINT64" | "QWORD" => Prim::UInt64,
        "LONGLONG" | "LONG64" | "INT64" => Prim::Int64,
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
    let doc = doc_attrs(&t.doc);
    Some(quote! { #doc pub type #name = #ty; })
}

// --- enums (constified) ----------------------------------------------------

/// Resolve an enum's constant values (implicit = previous + 1).
fn resolve_enum_vals(e: &Enum) -> Vec<(String, i128)> {
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
    vals
}

/// The integer `Prim` an enum is constified to (its Rust alignment == its size).
fn enum_repr_of(e: &Enum) -> Prim {
    enum_repr(e, &resolve_enum_vals(e))
}

fn emit_enum(e: &Enum) -> TokenStream {
    // Resolve constant values (implicit = previous + 1), then pick an underlying
    // integer type that fits them (or the fixed underlying type if declared).
    let vals = resolve_enum_vals(e);

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
            let doc = doc_attrs(&e.doc);
            quote! {
                #doc
                pub type #tn = #repr_tokens;
                #(#consts)*
            }
        }
        // Anonymous enum: no type alias, constants stand alone at `repr` type.
        None => quote! { #(#consts)* },
    }
}

fn enum_repr(e: &Enum, vals: &[(String, i128)]) -> Prim {
    if let Some(u) = &e.underlying
        && let Some(p) = resolve_prim(&ctype::parse(u), &BTreeMap::new()) {
            return p;
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
    let doc = doc_attrs(&f.doc);
    quote! { #doc pub fn #name(#(#params),*) #ret; }
}
