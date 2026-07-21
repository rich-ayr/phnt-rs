//! C `qualType` string → typed `CType` → Rust `syn`/`quote` tokens (spec §5, stage 4).
//!
//! Our AST is clang's JSON dump (spec §6), which reports every type only as a
//! `qualType` *string* (`"struct _UNICODE_STRING *"`, `"unsigned long"`,
//! `"WCHAR [260]"`) — there is no structured type-node tree the way libclang's C
//! API exposes. So faithful emission has to parse those strings. This module is
//! that parser plus the C→Rust type map.
//!
//! ## Coverage & fallback
//!
//! We parse the forms that actually occur in the phnt corpus: primitives (with
//! Windows **LLP64** sizing — `long` is 32-bit), named types, multi-level/const
//! pointers, (multi-dimensional) arrays, anonymous records (`(unnamed at LOC)`,
//! resolved to a synthetic name by `universe`), and function pointers. Anything
//! unrecognized becomes [`CType::Unknown`], which emits as a pointer-sized
//! `*mut c_void` (ABI-safe) and is *counted* so coverage gaps are visible rather
//! than silently mis-emitted.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

/// A parsed C type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CType {
    /// `void` — only valid as a pointer target or a function return.
    Void,
    Bool,
    Prim(Prim),
    /// A user/SDK type referenced by name (typedef, `struct`/`union`/`enum` tag).
    /// The leading `struct `/`union `/`enum ` tag word is stripped.
    Named(String),
    /// An anonymous record, keyed by its clang source location
    /// (`file:line:col`). `universe` rewrites these into [`CType::Named`] with a
    /// deterministic synthetic name before emission.
    Anon(String),
    /// `ptr32` marks an MSVC `__ptr32` pointer — **4 bytes** in 64-bit code
    /// (WoW64 thunk structs), emitted as a `u32` so its size/alignment is faithful.
    Pointer { konst: bool, ptr32: bool, inner: Box<CType> },
    Array { len: usize, inner: Box<CType> },
    FnPtr(FnPtr),
    /// A form the parser did not recognize (retained verbatim for diagnostics).
    /// Emits as `*mut c_void`.
    Unknown(String),
}

/// A primitive with a fixed Windows/LLP64 Rust mapping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Prim {
    Char,
    SChar,
    UChar,
    Short,
    UShort,
    Int,
    UInt,
    /// C `long` — **32-bit** on Windows (LLP64).
    Long,
    ULong,
    LongLong,
    ULongLong,
    /// MSVC `__int64`.
    Int64,
    UInt64,
    Float,
    Double,
    /// `wchar_t` — **16-bit** on Windows.
    WcharT,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FnPtr {
    pub ret: Box<CType>,
    pub params: Vec<CType>,
    pub cc: FnCc,
    pub variadic: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FnCc {
    C,
    Stdcall,
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

/// Parse a clang `qualType` string into a [`CType`].
pub fn parse(s: &str) -> CType {
    // The calling convention lives in an `__attribute__((stdcall))` that
    // `strip_attributes` will delete, so sniff it from the raw string first (a
    // qualType carries at most one CC; it binds the outermost declarator).
    let cc = if s.contains("stdcall") { FnCc::Stdcall } else { FnCc::C };
    let cleaned = strip_attributes(s);
    // After stripping an in-declarator attribute, `(__attribute__(..) *)`
    // collapses to `( *)`; renormalize so the fnptr matcher sees `(*`.
    let cleaned = cleaned.replace("( *", "(*");
    parse_inner_cc(cleaned.trim(), cc)
}

/// Remove every `__attribute__((...))` (balanced parens) and collapse runs of
/// whitespace to single spaces.
fn strip_attributes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if s[i..].starts_with("__attribute__") {
            // Skip the identifier, then a balanced `((...))`.
            let rest = &s[i + "__attribute__".len()..];
            let open = rest.find('(');
            if let Some(open) = open {
                let mut depth = 0usize;
                let mut j = i + "__attribute__".len() + open;
                let cb = s.as_bytes();
                while j < cb.len() {
                    match cb[j] {
                        b'(' => depth += 1,
                        b')' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    // Collapse whitespace.
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_inner(s: &str) -> CType {
    parse_inner_cc(s, FnCc::C)
}

fn parse_inner_cc(s: &str, cc: FnCc) -> CType {
    let s = s.trim();
    if s.is_empty() {
        return CType::Unknown(String::new());
    }

    // Function pointer: a `(*)` / `(CC *)` declarator with a trailing `(args)`.
    if let Some(fp) = try_parse_fnptr(s, cc) {
        return fp;
    }

    // Trailing arrays (outermost dimension is leftmost). Split base from the
    // `[..]` suffix, honoring that arrays of pointers use `T *[N]`.
    if let Some(open) = top_level_array_open(s) {
        let base = s[..open].trim();
        let dims = parse_dims(&s[open..]);
        let mut inner = parse_inner(base);
        for &len in dims.iter().rev() {
            inner = CType::Array { len, inner: Box::new(inner) };
        }
        return inner;
    }

    // Trailing pointer(s). The rightmost `*` is the outermost pointer. The tail
    // after it may hold only pointer qualifiers (`const`, MSVC `__ptr32`/
    // `__ptr64`/`__unaligned`). `__ptr32` makes the *outermost* pointer 4 bytes
    // (WoW64) — recorded so emit renders it as `u32` (see [`CType::Pointer`]).
    if let Some(star) = s.rfind('*') {
        let tail = s[star + 1..].trim();
        if tail.split_whitespace().all(is_ptr_qualifier) {
            let ptr32 = tail.split_whitespace().any(|w| w == "__ptr32");
            let head = s[..star].trim();
            // Pointee const-ness: east-const (`T const *`) or west-const
            // (`const T *`). Const vs mut is ABI-identical — this is cosmetic,
            // matched to bindgen's choice for the common single-level case.
            let konst = pointee_is_const(head);
            let inner = parse_inner(head);
            return CType::Pointer { konst, ptr32, inner: Box::new(inner) };
        }
    }

    parse_base(s)
}

/// Whether a pointer's pointee (the text left of its `*`) is `const`-qualified,
/// leading (`const T`) or trailing (`T const`).
fn pointee_is_const(head: &str) -> bool {
    let h = head.trim();
    h == "const" || h.starts_with("const ") || h.ends_with(" const")
}

/// A qualifier permitted after a `*` in a declarator (does not change the ABI
/// for our purposes; see the `__ptr32` note above).
fn is_ptr_qualifier(w: &str) -> bool {
    matches!(w, "const" | "volatile" | "__ptr32" | "__ptr64" | "__unaligned" | "restrict")
}

/// Parse a qualifier-stripped, pointer/array-free base type.
fn parse_base(s: &str) -> CType {
    // Strip leading cv / MSVC qualifiers (`const`, `volatile`, `__unaligned`).
    let mut b = s.trim();
    loop {
        if let Some(r) = b.strip_prefix("const ") {
            b = r.trim();
        } else if let Some(r) = b.strip_prefix("volatile ") {
            b = r.trim();
        } else if let Some(r) = b.strip_prefix("__unaligned ") {
            b = r.trim();
        } else {
            break;
        }
    }
    b = b.trim_end_matches("const").trim_end_matches("volatile").trim();

    // Anonymous record.
    if let Some(loc) = anon_loc(b) {
        return CType::Anon(loc);
    }

    // `struct`/`union`/`enum` tag prefix → the tag is a Named type.
    for tag in ["struct ", "union ", "enum "] {
        if let Some(rest) = b.strip_prefix(tag) {
            let rest = rest.trim();
            if let Some(loc) = anon_loc(rest) {
                return CType::Anon(loc);
            }
            return CType::Named(rest.to_string());
        }
    }

    if let Some(p) = prim(b) {
        return match p {
            PrimOrSpecial::Void => CType::Void,
            PrimOrSpecial::Bool => CType::Bool,
            PrimOrSpecial::Prim(p) => CType::Prim(p),
        };
    }

    if is_ident(b) {
        CType::Named(b.to_string())
    } else {
        CType::Unknown(b.to_string())
    }
}

enum PrimOrSpecial {
    Void,
    Bool,
    Prim(Prim),
}

fn prim(b: &str) -> Option<PrimOrSpecial> {
    use Prim::*;
    Some(match b {
        "void" => PrimOrSpecial::Void,
        "_Bool" | "bool" => PrimOrSpecial::Bool,
        "char" => PrimOrSpecial::Prim(Char),
        "signed char" => PrimOrSpecial::Prim(SChar),
        "unsigned char" => PrimOrSpecial::Prim(UChar),
        "short" | "short int" | "signed short" | "signed short int" => PrimOrSpecial::Prim(Short),
        "unsigned short" | "unsigned short int" => PrimOrSpecial::Prim(UShort),
        "int" | "signed" | "signed int" => PrimOrSpecial::Prim(Int),
        "unsigned" | "unsigned int" => PrimOrSpecial::Prim(UInt),
        "long" | "long int" | "signed long" | "signed long int" => PrimOrSpecial::Prim(Long),
        "unsigned long" | "unsigned long int" => PrimOrSpecial::Prim(ULong),
        "long long" | "long long int" | "signed long long" => PrimOrSpecial::Prim(LongLong),
        "unsigned long long" | "unsigned long long int" => PrimOrSpecial::Prim(ULongLong),
        "__int64" => PrimOrSpecial::Prim(Int64),
        "unsigned __int64" => PrimOrSpecial::Prim(UInt64),
        "__int32" => PrimOrSpecial::Prim(Int),
        "unsigned __int32" => PrimOrSpecial::Prim(UInt),
        "float" => PrimOrSpecial::Prim(Float),
        "double" | "long double" => PrimOrSpecial::Prim(Double),
        "wchar_t" | "__wchar_t" => PrimOrSpecial::Prim(WcharT),
        _ => return None,
    })
}

/// Extract an anonymous record's `FILE:LINE:COL` location key. clang spells
/// these two ways — `(unnamed at LOC)` and (scope-prefixed) `Parent::(anonymous
/// at LOC)` — but both carry the same loc, which is our stable synthetic-name
/// key, so we scan for either marker anywhere and ignore any scope prefix.
fn anon_loc(s: &str) -> Option<String> {
    let rest = if let Some(i) = s.find("(unnamed at ") {
        &s[i + "(unnamed at ".len()..]
    } else if let Some(i) = s.find("(anonymous at ") {
        &s[i + "(anonymous at ".len()..]
    } else {
        return None;
    };
    let inner = rest.strip_suffix(')')?;
    Some(inner.trim().to_string())
}

/// The byte index of the top-level `[` beginning the array suffix, if the type
/// is an array (i.e. the suffix from there is only `[..][..]` groups).
fn top_level_array_open(s: &str) -> Option<usize> {
    if !s.ends_with(']') {
        return None;
    }
    // Walk brackets from the right; find where the contiguous `[..]` run starts.
    let bytes = s.as_bytes();
    let mut i = s.len();
    loop {
        // Expect a `]` at i-1.
        if i == 0 || bytes[i - 1] != b']' {
            break;
        }
        // Find the matching `[`.
        let mut depth = 0usize;
        let mut j = i;
        let mut open = None;
        while j > 0 {
            j -= 1;
            match bytes[j] {
                b']' => depth += 1,
                b'[' => {
                    depth -= 1;
                    if depth == 0 {
                        open = Some(j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let open = open?;
        i = open;
        // Skip whitespace before the next group.
        while i > 0 && bytes[i - 1] == b' ' {
            i -= 1;
        }
        if i == 0 || bytes[i - 1] != b']' {
            return Some(i);
        }
    }
    None
}

/// Parse a `[a][b]...` suffix into its dimensions (unsized `[]` → 0).
fn parse_dims(s: &str) -> Vec<usize> {
    let mut dims = Vec::new();
    let mut rest = s;
    while let Some(open) = rest.find('[') {
        let close = match rest[open..].find(']') {
            Some(c) => open + c,
            None => break,
        };
        let n = rest[open + 1..close].trim();
        dims.push(n.parse::<usize>().unwrap_or(0));
        rest = &rest[close + 1..];
    }
    dims
}

/// Recognize and parse function pointers `RET (*)(ARGS)` *and* bare function
/// types `RET (ARGS)`. Both decay to a Rust `Option<fn>` (matching bindgen): a
/// C `typedef RET FOO(ARGS)` and `typedef RET (*PFOO)(ARGS)` are used
/// interchangeably as callbacks. `cc` is sniffed from the pre-strip string.
fn try_parse_fnptr(s: &str, cc: FnCc) -> Option<CType> {
    if !s.ends_with(')') {
        return None;
    }
    // The parameter list is the final top-level `(...)` group.
    let arg_open = matching_open_for_last_close(s)?;
    let args = &s[arg_open + 1..s.len() - 1];
    // An anonymous record — `(unnamed at ...)` or `Parent::(anonymous at ...)` —
    // also ends with `)`. Reject: it's a type, not a function's parameter list.
    let at = args.trim_start();
    if at.starts_with("unnamed at") || at.starts_with("anonymous at") {
        return None;
    }
    let decl = s[..arg_open].trim();
    // Pointer-to-function (`RET (*)`) vs bare function type (`RET`).
    let ret_str = match decl.find("(*") {
        Some(dp) => decl[..dp].trim(),
        None => decl,
    };
    if ret_str.is_empty() || matches!(ret_str, "struct" | "union" | "enum") {
        return None;
    }
    // Guard against catching non-type parenthesized noise: the return must parse
    // to a real type.
    let ret = parse_inner(ret_str);
    if matches!(ret, CType::Unknown(_)) {
        return None;
    }

    let mut variadic = false;
    let mut params = Vec::new();
    for raw in split_top_level_commas(args) {
        let a = raw.trim();
        if a.is_empty() || a == "void" {
            continue;
        }
        if a == "..." {
            variadic = true;
            continue;
        }
        params.push(parse_inner(a));
    }

    Some(CType::FnPtr(FnPtr { ret: Box::new(ret), params, cc, variadic }))
}

/// Index of the `(` that matches the string's final `)`, scanning right-to-left
/// with depth counting (handles nested fn-pointer parameters).
fn matching_open_for_last_close(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.last() != Some(&b')') {
        return None;
    }
    let mut depth = 0usize;
    let mut i = s.len();
    while i > 0 {
        i -= 1;
        match b[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split on commas that are not nested inside parens/brackets.
fn split_top_level_commas(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in s.chars() {
        match ch {
            '(' | '[' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.chars().next().unwrap().is_ascii_digit()
}

// ---------------------------------------------------------------------------
// Transforms used by `universe` / `emit`
// ---------------------------------------------------------------------------

impl CType {
    /// Apply `f` to every `Named`/`Anon` leaf, in place. Used to resolve
    /// anonymous locations to synthetic names and to rewrite typedef aliases.
    pub fn map_leaves(&mut self, f: &mut impl FnMut(&mut CType)) {
        match self {
            CType::Pointer { inner, .. } | CType::Array { inner, .. } => inner.map_leaves(f),
            CType::FnPtr(fp) => {
                fp.ret.map_leaves(f);
                for p in &mut fp.params {
                    p.map_leaves(f);
                }
            }
            CType::Named(_) | CType::Anon(_) => f(self),
            _ => {}
        }
    }

    /// Collect referenced type names (for the closure). Emits `Named` names and
    /// `Anon` location keys (the caller resolves anon → synthetic name).
    pub fn collect_refs<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            CType::Pointer { inner, .. } | CType::Array { inner, .. } => inner.collect_refs(out),
            CType::FnPtr(fp) => {
                fp.ret.collect_refs(out);
                for p in &fp.params {
                    p.collect_refs(out);
                }
            }
            CType::Named(n) | CType::Anon(n) => out.push(n),
            _ => {}
        }
    }

    /// Render to Rust tokens. `Named` idents are emitted verbatim (sanitized by
    /// the caller's naming pass); `Anon`/`Unknown` fall back to `*mut c_void`.
    pub fn to_rust(&self) -> TokenStream {
        match self {
            CType::Void => quote!(::core::ffi::c_void),
            CType::Bool => quote!(bool),
            CType::Prim(p) => p.to_rust(),
            CType::Named(n) => {
                let id = format_ident!("{}", sanitize_ident(n));
                quote!(#id)
            }
            CType::Anon(_) | CType::Unknown(_) => quote!(*mut ::core::ffi::c_void),
            // A `__ptr32` pointer is a 4-byte WoW64 pointer; emit `u32` for a
            // faithful size/alignment (it is not natively dereferenceable on x64).
            CType::Pointer { ptr32: true, .. } => quote!(u32),
            CType::Pointer { konst, inner, ptr32: false } => {
                let it = inner.to_rust_ptr_target();
                if *konst {
                    quote!(*const #it)
                } else {
                    quote!(*mut #it)
                }
            }
            CType::Array { len, inner } => {
                let it = inner.to_rust();
                let n = *len;
                quote!([#it; #n])
            }
            CType::FnPtr(fp) => fp.to_rust(),
        }
    }

    /// Pointer targets: `void*` becomes `*mut c_void`'s target `c_void`, and a
    /// bare `void` target stays `c_void` (never unit).
    fn to_rust_ptr_target(&self) -> TokenStream {
        self.to_rust()
    }
}

impl Prim {
    /// Render to a **concrete** Rust integer/float type with the Windows/LLP64
    /// meaning baked in — deliberately NOT `::core::ffi::c_*`.
    ///
    /// `::core::ffi`'s widths and signedness track the *host* target, not Windows:
    /// `c_char` is unsigned on aarch64 (Windows `char` is signed → `i8`), and
    /// `c_long`/`c_ulong` are 64-bit on any LP64 target (Windows LLP64 keeps them
    /// 32-bit). These bindings describe the Windows ABI, so a build for aarch64 or
    /// a non-Windows host (docs/CI) must not let `::core::ffi` reinterpret them —
    /// that would silently corrupt signedness and field widths. The `phnt` crate's
    /// forked `cty` module pins exactly these types; emitting the pinned concrete
    /// type directly gives the same guarantee with no dependency and keeps the
    /// generated `ffi` self-contained (so it still compiles standalone).
    ///
    /// `void` and opaque pointees stay `::core::ffi::c_void` (its one non-numeric
    /// case, which `cty::c_void` also just re-exports).
    pub fn to_rust(&self) -> TokenStream {
        use Prim::*;
        match self {
            Char => quote!(i8), // MSVC `char` is signed
            SChar => quote!(i8),
            UChar => quote!(u8),
            Short => quote!(i16),
            UShort => quote!(u16),
            Int => quote!(i32),
            UInt => quote!(u32),
            Long => quote!(i32),  // LLP64: `long` is 32-bit
            ULong => quote!(u32), // LLP64: `unsigned long` is 32-bit
            LongLong => quote!(i64),
            ULongLong => quote!(u64),
            Int64 => quote!(i64),
            UInt64 => quote!(u64),
            Float => quote!(f32),
            Double => quote!(f64),
            WcharT => quote!(u16), // Windows `wchar_t` is 16-bit
        }
    }
}

impl FnPtr {
    pub fn to_rust(&self) -> TokenStream {
        let abi = match self.cc {
            FnCc::C => "C",
            FnCc::Stdcall => "system",
        };
        let params = self.params.iter().map(|p| p.to_rust());
        let ret = match &*self.ret {
            CType::Void => quote!(),
            other => {
                let t = other.to_rust();
                quote!(-> #t)
            }
        };
        let variadic = if self.variadic { quote!(, ...) } else { quote!() };
        quote!(::core::option::Option<unsafe extern #abi fn(#(#params),* #variadic) #ret>)
    }
}

/// Render a `CType` to a readable Rust type string (for diagnostics).
pub fn render_debug(t: &CType) -> String {
    t.to_rust().to_string().replace(" :: ", "::").replace(":: ", "::")
}

/// Make a C identifier a valid Rust identifier. Most keywords raw-escape
/// (`r#type`); the few that cannot be raw (`Self`, `self`, `super`, `crate`,
/// `_`) get a trailing underscore instead.
pub fn sanitize_ident(name: &str) -> String {
    // Keywords that CANNOT be raw identifiers — mangle with a trailing `_`.
    const NON_RAW: &[&str] = &["Self", "self", "super", "crate", "_"];
    if NON_RAW.contains(&name) {
        return format!("{name}_");
    }
    // Keywords that must be raw-escaped to be used as identifiers.
    const KEYWORDS: &[&str] = &[
        "type", "fn", "in", "ref", "match", "move", "box", "loop", "as", "use", "mod", "impl",
        "dyn", "async", "await", "become", "final", "override", "priv", "typeof", "unsized",
        "virtual", "yield", "where", "let", "const", "static", "struct", "enum", "union", "trait",
        "pub", "mut", "if", "else", "for", "while", "return", "break", "continue", "true", "false",
        "unsafe", "extern", "fn", "abstract", "do", "macro",
    ];
    if KEYWORDS.contains(&name) {
        format!("r#{name}")
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> CType {
        parse(s)
    }

    #[test]
    fn primitives_llp64() {
        assert_eq!(p("void"), CType::Void);
        assert_eq!(p("unsigned long"), CType::Prim(Prim::ULong));
        assert_eq!(p("long"), CType::Prim(Prim::Long));
        assert_eq!(p("unsigned __int64"), CType::Prim(Prim::UInt64));
        assert_eq!(p("wchar_t"), CType::Prim(Prim::WcharT));
        assert_eq!(p("_Bool"), CType::Bool);
    }

    #[test]
    fn named_and_tags() {
        assert_eq!(p("ULONG"), CType::Named("ULONG".into()));
        assert_eq!(p("struct _UNICODE_STRING"), CType::Named("_UNICODE_STRING".into()));
        assert_eq!(p("union _LARGE_INTEGER"), CType::Named("_LARGE_INTEGER".into()));
        assert_eq!(p("const GUID"), CType::Named("GUID".into()));
    }

    #[test]
    fn pointers() {
        assert_eq!(
            p("struct _UNICODE_STRING *"),
            CType::Pointer {
                konst: false,
                ptr32: false,
                inner: Box::new(CType::Named("_UNICODE_STRING".into())),
            }
        );
        assert_eq!(
            p("const wchar_t *"),
            CType::Pointer { konst: true, ptr32: false, inner: Box::new(CType::Prim(Prim::WcharT)) }
        );
        // Double pointer.
        assert_eq!(
            p("void **"),
            CType::Pointer {
                konst: false,
                ptr32: false,
                inner: Box::new(CType::Pointer {
                    konst: false,
                    ptr32: false,
                    inner: Box::new(CType::Void),
                }),
            }
        );
        // `__ptr32` — a 4-byte WoW64 pointer, rendered as `u32`.
        let p32 = p("void * __ptr32");
        assert_eq!(
            p32,
            CType::Pointer { konst: false, ptr32: true, inner: Box::new(CType::Void) }
        );
        assert_eq!(p32.to_rust().to_string(), "u32");
    }

    #[test]
    fn arrays() {
        assert_eq!(
            p("WCHAR [260]"),
            CType::Array { len: 260, inner: Box::new(CType::Named("WCHAR".into())) }
        );
        // Multidim: outer dimension leftmost → [[u8;3];2].
        let t = p("unsigned char [2][3]");
        assert_eq!(
            t,
            CType::Array {
                len: 2,
                inner: Box::new(CType::Array {
                    len: 3,
                    inner: Box::new(CType::Prim(Prim::UChar)),
                }),
            }
        );
    }

    #[test]
    fn anonymous() {
        assert_eq!(
            p("struct (unnamed at C:\\x\\winnt.h:945:5)"),
            CType::Anon("C:\\x\\winnt.h:945:5".into())
        );
        // Anon with pointer decoration.
        assert_eq!(
            p("struct (unnamed at f.h:1:2) *"),
            CType::Pointer { konst: false, ptr32: false, inner: Box::new(CType::Anon("f.h:1:2".into())) }
        );
    }

    #[test]
    fn attributes_stripped() {
        // A stdcall fn pointer with attribute noise.
        let t = p("void (*)(void *) __attribute__((stdcall))");
        match t {
            CType::FnPtr(fp) => {
                assert_eq!(fp.params.len(), 1);
                assert_eq!(*fp.ret, CType::Void);
            }
            other => panic!("expected fnptr, got {other:?}"),
        }
    }

    #[test]
    fn bare_function_type() {
        // `typedef NTSTATUS FOO(PVOID)` → the target qualType is a bare fn type.
        match p("NTSTATUS (PVOID)") {
            CType::FnPtr(fp) => {
                assert_eq!(fp.params.len(), 1);
                assert_eq!(*fp.ret, CType::Named("NTSTATUS".into()));
            }
            other => panic!("expected fnptr, got {other:?}"),
        }
        match p("void (void)") {
            CType::FnPtr(fp) => {
                assert_eq!(fp.params.len(), 0);
                assert_eq!(*fp.ret, CType::Void);
            }
            other => panic!("expected fnptr, got {other:?}"),
        }
    }

    #[test]
    fn anon_record_not_misread_as_fnptr() {
        // Ends with `)` but is an anonymous record, not a function type.
        assert_eq!(
            p("struct (unnamed at f.h:1:2)"),
            CType::Anon("f.h:1:2".into())
        );
    }

    #[test]
    fn fnptr_stdcall_in_declarator() {
        let t = p("long (__attribute__((stdcall)) *)(void *, unsigned long)");
        match t {
            CType::FnPtr(fp) => {
                assert_eq!(fp.cc, FnCc::Stdcall);
                assert_eq!(fp.params.len(), 2);
            }
            other => panic!("expected fnptr, got {other:?}"),
        }
    }
}
