//! Typed intermediate representation (spec §5, stage 3; §7 `ir`).
//!
//! Deserializes clang's `-ast-dump=json` via the `clang-ast` crate and lowers the
//! declarations that originate in phnt headers into a typed IR (records, enums,
//! typedefs, functions). Each item carries its source file and — for functions —
//! the calling convention parsed from the AST type (spec §4c; don't assume
//! `extern "C"`). C types are retained as `qualType` strings; the C→Rust mapping
//! happens in `emit`.
//!
//! ## clang-ast model
//!
//! `clang_ast::Node<Clang>` frames every node as `{ id, kind, inner }`. Our
//! `Clang` enum is internally tagged on `kind`; variants we don't model collapse
//! to `Other`. Children (fields, params, enum constants, bitfield widths) live in
//! `node.inner`, so lowering walks the node tree rather than nesting them in the
//! variant structs. clang omits a `loc.file` when it equals the previous node's;
//! `clang-ast` resolves that inheritance for us (its `BareSourceLocation.file` is
//! always populated), so per-node file attribution is reliable in one ordered
//! pass.

use std::path::Path;

use anyhow::{Context, Result};
use clang_ast::SourceLocation;
use serde::Deserialize;

use crate::ctype::{self, CType};

/// A node in the clang AST, specialized to the kinds we care about.
pub type Node = clang_ast::Node<Clang>;

/// Shared C-type descriptor (`"type": { "qualType", "desugaredQualType" }`).
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TypeInfo {
    pub qual_type: Option<String>,
    pub desugared_qual_type: Option<String>,
}

impl TypeInfo {
    /// The most-sugared spelling (what the source wrote), e.g. `ULONG` not
    /// `unsigned long`. Faithful emission maps this; the desugared form is a
    /// fallback / cross-check.
    pub fn c_type(&self) -> &str {
        self.qual_type.as_deref().unwrap_or("")
    }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TypedefDecl {
    pub name: Option<String>,
    pub loc: Option<SourceLocation>,
    #[serde(default)]
    pub is_implicit: bool,
    #[serde(rename = "type")]
    pub ty: TypeInfo,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RecordDecl {
    pub name: Option<String>,
    pub loc: Option<SourceLocation>,
    /// Source range; `range.begin` is a loc fallback when `loc` is `{}` (clang
    /// elides `loc` on some nested anonymous records even though their type name
    /// still carries the real `(anonymous at FILE:LINE:COL)`).
    pub range: Option<clang_ast::SourceRange>,
    /// `"struct"` | `"union"` | (rarely) `"class"`.
    pub tag_used: Option<String>,
    #[serde(default)]
    pub is_implicit: bool,
    /// A forward declaration has no `completeDefinition`.
    #[serde(default)]
    pub complete_definition: bool,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FieldDecl {
    pub name: Option<String>,
    pub loc: Option<SourceLocation>,
    #[serde(rename = "type")]
    pub ty: TypeInfo,
    #[serde(default)]
    pub is_bitfield: bool,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EnumDecl {
    pub name: Option<String>,
    pub loc: Option<SourceLocation>,
    pub range: Option<clang_ast::SourceRange>,
    /// Present when the enum has an explicit `: type` fixed underlying type.
    #[serde(rename = "fixedUnderlyingType", default)]
    pub fixed_underlying_type: Option<TypeInfo>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EnumConstantDecl {
    pub name: Option<String>,
    pub loc: Option<SourceLocation>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FunctionDecl {
    pub name: Option<String>,
    pub loc: Option<SourceLocation>,
    pub mangled_name: Option<String>,
    #[serde(default)]
    pub is_implicit: bool,
    /// `true` for `__forceinline`/`inline` helpers. clang reports this even when
    /// the body is elided, but we key skip/keep off body presence (a
    /// `CompoundStmt` child) — see `lower_function`.
    #[serde(default)]
    pub inline: bool,
    /// `"static"`, `"extern"`, or absent. Retained for the inline-fn inventory.
    pub storage_class: Option<String>,
    #[serde(rename = "type")]
    pub ty: TypeInfo,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ParmVarDecl {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub ty: TypeInfo,
}

/// A `ConstantExpr` / `IntegerLiteral` carrying an evaluated `value` string —
/// used for bitfield widths and explicit enum constant values.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct ValueExpr {
    pub value: Option<String>,
}

/// The clang AST node kinds we model. Variant names must match clang's `kind`
/// strings exactly; `clang-ast` drives selection via its own `deserialize_enum`
/// (NOT serde internal tagging — that path can't handle clang's kind-less `{}`
/// placeholder nodes). The literal `Other` variant catches every unmodeled kind
/// *and* those empty nodes.
#[derive(Deserialize, Clone, Debug)]
pub enum Clang {
    TranslationUnitDecl,
    TypedefDecl(TypedefDecl),
    RecordDecl(RecordDecl),
    FieldDecl(FieldDecl),
    EnumDecl(EnumDecl),
    EnumConstantDecl(EnumConstantDecl),
    FunctionDecl(FunctionDecl),
    ParmVarDecl(ParmVarDecl),
    ConstantExpr(ValueExpr),
    IntegerLiteral(ValueExpr),
    /// A function *body*. Its presence as a `FunctionDecl` child marks that decl
    /// as a definition (an inline helper here) rather than a bare prototype.
    CompoundStmt,
    Other,
}

// ---------------------------------------------------------------------------
// IR
// ---------------------------------------------------------------------------

/// The lowered per-config IR: the phnt declarations from one matrix cell.
#[derive(Clone, Debug, Default)]
pub struct Module {
    pub records: Vec<Record>,
    pub enums: Vec<Enum>,
    pub typedefs: Vec<Typedef>,
    /// Linkable prototypes (no body) — the extern FFI surface bindgen also shipped.
    pub functions: Vec<Function>,
    /// Inline-*defined* helpers (a body was present): `__forceinline`/`static
    /// inline` convenience like `Rtl*` safe-int math and `_umul128`. They have no
    /// exported symbol, so they can't be `extern` decls, and we ship committed
    /// bindings with no build-time C compiler — bindgen never emitted them either.
    /// We skip them from `ffi` and inventory them here as the `ext` worklist
    /// (project decision, 2026-07-21).
    pub inline_functions: Vec<Function>,
}

impl Module {
    /// Total emitted-surface items (excludes the skipped inline inventory).
    pub fn total(&self) -> usize {
        self.records.len() + self.enums.len() + self.typedefs.len() + self.functions.len()
    }
}

#[derive(Clone, Debug)]
pub struct Record {
    /// Real tag name, or a synthetic `<parent>__anon<N>` for a hoisted anonymous
    /// member (always `Some` after lowering).
    pub name: Option<String>,
    pub is_union: bool,
    pub fields: Vec<Field>,
    pub file: String,
    /// `true` if this record was hoisted from an anonymous member.
    pub anon: bool,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: Option<String>,
    /// Parsed + anon-resolved type. Anonymous member types have been rewritten to
    /// the hoisted record's synthetic `Named` (see `lower_record`).
    pub ty: CType,
    /// Bit width for bitfield members.
    pub bitfield_width: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Enum {
    pub name: Option<String>,
    pub underlying: Option<String>,
    pub constants: Vec<EnumConst>,
    pub file: String,
}

#[derive(Clone, Debug)]
pub struct EnumConst {
    pub name: String,
    /// Explicit value if the source assigned one; otherwise implicit
    /// (previous + 1), resolved in `emit`.
    pub value: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Typedef {
    pub name: String,
    pub ty: CType,
    pub file: String,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub name: String,
    pub c_return_and_params: String,
    /// Parsed return type (from the function's `RET (ARGS)` qualType).
    pub ret: CType,
    pub params: Vec<Param>,
    /// Calling convention parsed from the AST type, e.g. `stdcall` (spec §4c).
    pub calling_conv: CallingConv,
    /// `true` when the decl carried a body (`CompoundStmt`): an inline-defined
    /// helper routed to `Module::inline_functions`, not the extern surface.
    pub inline_defined: bool,
    /// `"static"` / `"extern"` / `None`, and whether `inline`/`__forceinline` —
    /// retained so the inventory can annotate each skipped helper.
    pub storage_class: Option<String>,
    pub inline_keyword: bool,
    pub file: String,
}

#[derive(Clone, Debug)]
pub struct Param {
    pub name: Option<String>,
    pub ty: CType,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CallingConv {
    /// The target default (C ABI) — no explicit attribute on the AST type.
    Default,
    Stdcall,
    Fastcall,
    Cdecl,
    Vectorcall,
}

impl CallingConv {
    /// Parse from a clang function `qualType`, e.g.
    /// `long (void *) __attribute__((stdcall))`.
    fn from_qual_type(q: &str) -> Self {
        if q.contains("__attribute__((stdcall))") || q.contains("__stdcall") {
            CallingConv::Stdcall
        } else if q.contains("__attribute__((fastcall))") || q.contains("__fastcall") {
            CallingConv::Fastcall
        } else if q.contains("__attribute__((cdecl))") || q.contains("__cdecl") {
            CallingConv::Cdecl
        } else if q.contains("__attribute__((vectorcall))") || q.contains("__vectorcall") {
            CallingConv::Vectorcall
        } else {
            CallingConv::Default
        }
    }
}

// ---------------------------------------------------------------------------
// Parse + lower
// ---------------------------------------------------------------------------

/// Deserialize a clang JSON AST from disk into the typed node tree.
pub fn parse_ast(path: &Path) -> Result<Node> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening AST {}", path.display()))?;
    let reader = std::io::BufReader::with_capacity(1 << 20, file);
    let node: Node = serde_json::from_reader(reader)
        .with_context(|| format!("deserializing AST {}", path.display()))?;
    Ok(node)
}

/// Resolve the source file a node lives in (spelling location preferred).
fn node_file(loc: &Option<SourceLocation>) -> Option<String> {
    let loc = loc.as_ref()?;
    let bare = loc.spelling_loc.as_ref().or(loc.expansion_loc.as_ref())?;
    Some(bare.file.to_string())
}

/// Is `file` a phnt header (under `deps/phnt-nightly`)? Filters out the Windows
/// SDK, the CRT, and clang builtins. Slash-insensitive.
fn is_phnt_file(file: &str) -> bool {
    let norm = file.replace('\\', "/").to_ascii_lowercase();
    norm.contains("phnt-nightly/") || norm.contains("phnt_nightly/")
}

/// Lower a whole AST into the phnt-only IR for one config cell.
pub fn lower(root: &Node) -> Module {
    let mut m = Module::default();
    for node in &root.inner {
        match &node.kind {
            Clang::RecordDecl(r) => {
                if r.is_implicit || !r.complete_definition {
                    continue;
                }
                let Some(name) = r.name.clone() else { continue };
                let Some(file) = node_file(&r.loc) else { continue };
                if !is_phnt_file(&file) {
                    continue;
                }
                // Recursive: hoists nested anonymous members into `m.records`.
                lower_record(node, name, file, false, &mut m.records);
            }
            Clang::EnumDecl(e) => {
                let Some(file) = node_file(&e.loc) else { continue };
                if !is_phnt_file(&file) {
                    continue;
                }
                m.enums.push(lower_enum(node, e, file));
            }
            Clang::TypedefDecl(t) => {
                if t.is_implicit {
                    continue;
                }
                let Some(name) = t.name.clone() else { continue };
                let Some(file) = node_file(&t.loc) else { continue };
                if !is_phnt_file(&file) {
                    continue;
                }
                m.typedefs.push(Typedef { name, ty: ctype::parse(t.ty.c_type()), file });
            }
            Clang::FunctionDecl(f) => {
                if f.is_implicit {
                    continue;
                }
                let Some(name) = f.name.clone() else { continue };
                let Some(file) = node_file(&f.loc) else { continue };
                if !is_phnt_file(&file) {
                    continue;
                }
                let func = lower_function(node, f, name, file);
                if func.inline_defined {
                    m.inline_functions.push(func);
                } else {
                    m.functions.push(func);
                }
            }
            _ => {}
        }
    }
    m
}

/// Does a parsed type reference an (unresolved) anonymous record?
fn has_anon(t: &CType) -> bool {
    match t {
        CType::Anon(_) => true,
        CType::Pointer { inner, .. } | CType::Array { inner, .. } => has_anon(inner),
        CType::FnPtr(fp) => has_anon(&fp.ret) || fp.params.iter().any(has_anon),
        _ => false,
    }
}

/// Lower one record node into `out`, **recursively hoisting anonymous members**.
///
/// An anonymous struct/union member has no name, so it can only be referenced
/// from *this* record — clang emits the anon `RecordDecl` immediately before the
/// `FieldDecl` that uses it. We exploit exactly that structural adjacency: the
/// nameless nested `RecordDecl`s, taken in source order, line up 1:1 with the
/// fields whose type is anonymous. Each such field is given a synthetic
/// `<parent>__anon<N>` type and the referenced record is hoisted under that name
/// (recursively, for anon-in-anon). No source coordinates are used as keys.
///
/// Reused by `emit` to lower external (SDK) records pulled in by the closure.
pub fn lower_record(node: &Node, name: String, file: String, anon: bool, out: &mut Vec<Record>) {
    let Clang::RecordDecl(r) = &node.kind else { return };
    let is_union = r.tag_used.as_deref() == Some("union");

    // Nameless nested record definitions, in source order — the hoist queue.
    let anon_defs: Vec<&Node> = node
        .inner
        .iter()
        .filter(|c| matches!(&c.kind, Clang::RecordDecl(cr) if cr.complete_definition && cr.name.is_none()))
        .collect();

    let mut fields = Vec::new();
    let mut hoist: Vec<(String, &Node)> = Vec::new();
    let mut anon_idx = 0usize;

    for child in &node.inner {
        let Clang::FieldDecl(fd) = &child.kind else { continue };
        let mut ty = ctype::parse(fd.ty.c_type());
        if has_anon(&ty) {
            if let Some(anon_node) = anon_defs.get(anon_idx).copied() {
                anon_idx += 1;
                let synth = format!("{name}__anon{anon_idx}");
                ty.map_leaves(&mut |leaf| {
                    if matches!(leaf, CType::Anon(_)) {
                        *leaf = CType::Named(synth.clone());
                    }
                });
                hoist.push((synth, anon_node));
            }
            // else: no matching anon def (shouldn't happen) — leaf stays `Anon`,
            // which emit renders as an opaque placeholder + logs.
        }
        let bitfield_width = if fd.is_bitfield {
            child.inner.iter().find_map(|n| match &n.kind {
                Clang::ConstantExpr(v) | Clang::IntegerLiteral(v) => v.value.clone(),
                _ => None,
            })
        } else {
            None
        };
        fields.push(Field { name: fd.name.clone(), ty, bitfield_width });
    }

    out.push(Record { name: Some(name), is_union, fields, file: file.clone(), anon });

    for (synth, anon_node) in hoist {
        lower_record(anon_node, synth, file.clone(), true, out);
    }
}

/// Lower a record `Node` (from the universe index) into `out`, recursively —
/// used by `emit` to pull in external SDK records reached by the closure.
pub fn lower_record_node(node: &Node, out: &mut Vec<Record>) {
    if let Clang::RecordDecl(r) = &node.kind {
        if let Some(name) = r.name.clone() {
            let file = node_file(&r.loc).unwrap_or_default();
            lower_record(node, name, file, false, out);
        }
    }
}

/// Lower an enum `Node` (from the universe index), for `emit`'s closure.
pub fn lower_enum_node(node: &Node) -> Option<Enum> {
    if let Clang::EnumDecl(e) = &node.kind {
        let file = node_file(&e.loc).unwrap_or_default();
        Some(lower_enum(node, e, file))
    } else {
        None
    }
}

/// Lower a typedef `Node` (from the universe index), for `emit`'s closure.
pub fn lower_typedef_node(node: &Node) -> Option<Typedef> {
    if let Clang::TypedefDecl(t) = &node.kind {
        let name = t.name.clone()?;
        let file = node_file(&t.loc).unwrap_or_default();
        Some(Typedef { name, ty: ctype::parse(t.ty.c_type()), file })
    } else {
        None
    }
}

fn lower_enum(node: &Node, e: &EnumDecl, file: String) -> Enum {
    let mut constants = Vec::new();
    for child in &node.inner {
        if let Clang::EnumConstantDecl(c) = &child.kind {
            let Some(name) = c.name.clone() else { continue };
            let value = child.inner.iter().find_map(|n| match &n.kind {
                Clang::ConstantExpr(v) | Clang::IntegerLiteral(v) => v.value.clone(),
                _ => None,
            });
            constants.push(EnumConst { name, value });
        }
    }
    let underlying = e.fixed_underlying_type.as_ref().map(|t| t.c_type().to_string());
    Enum { name: e.name.clone(), underlying, constants, file }
}

fn lower_function(node: &Node, f: &FunctionDecl, name: String, file: String) -> Function {
    let mut params = Vec::new();
    let mut inline_defined = false;
    for child in &node.inner {
        match &child.kind {
            Clang::ParmVarDecl(p) => {
                params.push(Param { name: p.name.clone(), ty: ctype::parse(p.ty.c_type()) });
            }
            // A body child = this is a *definition* (inline helper), not a
            // linkable prototype. The single reliable skip signal.
            Clang::CompoundStmt => inline_defined = true,
            _ => {}
        }
    }
    // The function type parses as `RET (ARGS)` → a bare-fn-type `FnPtr`; take its
    // return. (Param names come from the `ParmVarDecl`s above, not this.)
    let ret = match ctype::parse(f.ty.c_type()) {
        CType::FnPtr(fp) => *fp.ret,
        other => other,
    };
    Function {
        name,
        c_return_and_params: f.ty.c_type().to_string(),
        ret,
        params,
        calling_conv: CallingConv::from_qual_type(f.ty.c_type()),
        inline_defined,
        storage_class: f.storage_class.clone(),
        inline_keyword: f.inline,
        file,
    }
}
