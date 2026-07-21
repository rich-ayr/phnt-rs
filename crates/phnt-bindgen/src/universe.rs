//! TU-wide type index for the self-containment closure (spec §5, stage 4).
//!
//! phnt records/functions reference types defined *outside* phnt (SDK primitives
//! like `UNICODE_STRING`, `LARGE_INTEGER`, `GUID`, `HANDLE`, `CLIENT_ID`,
//! `LIST_ENTRY`). The output crate is **raw and self-contained** — no
//! `windows-sys` — so emission must pull every transitively-referenced type in
//! itself, from the *same* AST (guaranteeing the target's real layout).
//!
//! This module indexes every **named** record/enum/typedef in the translation
//! unit (not just phnt files) by name. `emit` seeds a worklist with the
//! phnt-origin roots and walks name references to the fixpoint.
//!
//! Anonymous records are **not** indexed here. They can only be referenced from
//! within the record that lexically contains them (an injected member), so they
//! resolve *parent-locally* during recursive record lowering (`ir::lower_record`)
//! — by structural adjacency, needing neither a global loc key nor `(line,col)`
//! (both of which proved unreliable: clang misattributes the anon record's file,
//! and `(line,col)` collides across files).

use std::collections::HashMap;

use crate::ctype::{self, CType};
use crate::ir::{Clang, Node};

/// References into the parsed AST, keyed by name for closure resolution.
#[derive(Default)]
pub struct Index<'a> {
    pub rec_by_name: HashMap<String, &'a Node>,
    pub enum_by_name: HashMap<String, &'a Node>,
    pub typedef_by_name: HashMap<String, &'a Node>,
    /// `typedef struct {…} T;` — the SDK's anonymous-struct-typedef idiom. clang
    /// gives the struct the typedef name only "for linkage" in qualTypes (so it
    /// looks like a self-alias `typedef T T;`) while the `RecordDecl` itself is
    /// anonymous and *not* in `rec_by_name`. Maps the typedef name → that
    /// anonymous `RecordDecl`, so `emit` can render it as `struct T {…}` instead
    /// of a dangling opaque. (Common in winnt.h/winuser.h: `POWER_ACTION_POLICY`,
    /// `FLASHWINFO`, …)
    pub anon_typedef_rec: HashMap<String, &'a Node>,
    /// Same idiom for `typedef enum {…} T;` → the anonymous `EnumDecl` (e.g.
    /// `POWER_ACTION`, `POWER_MONITOR_REQUEST_REASON`). Emitted as a constified
    /// enum named `T` rather than an opaque struct (which would be 0-sized).
    pub anon_typedef_enum: HashMap<String, &'a Node>,
}

/// Recursively index every named type-defining decl in the TU (records/unions
/// nest inside records, so this walks the whole tree, not just the top level).
/// First complete definition wins; forward declarations are skipped.
pub fn build_index(root: &Node) -> Index<'_> {
    let mut idx = Index::default();
    walk(root, &mut idx);
    idx
}

fn walk<'a>(node: &'a Node, idx: &mut Index<'a>) {
    match &node.kind {
        Clang::RecordDecl(r) if r.complete_definition => {
            if let Some(name) = &r.name {
                idx.rec_by_name.entry(name.clone()).or_insert(node);
            }
        }
        Clang::EnumDecl(e) => {
            if let Some(name) = &e.name {
                idx.enum_by_name.entry(name.clone()).or_insert(node);
            }
        }
        Clang::TypedefDecl(t) => {
            if let Some(name) = &t.name {
                idx.typedef_by_name.entry(name.clone()).or_insert(node);
            }
        }
        _ => {}
    }

    // Detect the `typedef struct {…} T;` idiom among these children: a self-alias
    // typedef (underlying prints as its own name `T`, clang's linkage name for
    // the anonymous struct) is preceded — skipping doc-comment nodes — by an
    // anonymous complete `RecordDecl`, which is that struct's definition.
    for (i, child) in node.inner.iter().enumerate() {
        let Clang::TypedefDecl(t) = &child.kind else { continue };
        let Some(tname) = &t.name else { continue };
        let self_alias = matches!(ctype::parse(t.ty.c_type()), CType::Named(n) if n == *tname);
        if !self_alias {
            continue;
        }
        for prev in node.inner[..i].iter().rev() {
            match &prev.kind {
                // Doc comments (and other unmodeled nodes) collapse to `Other`.
                Clang::Other => continue,
                Clang::RecordDecl(pr) if pr.complete_definition && pr.name.is_none() => {
                    idx.anon_typedef_rec.entry(tname.clone()).or_insert(prev);
                    break;
                }
                Clang::EnumDecl(pe) if pe.name.is_none() => {
                    idx.anon_typedef_enum.entry(tname.clone()).or_insert(prev);
                    break;
                }
                _ => break,
            }
        }
    }

    for child in &node.inner {
        walk(child, idx);
    }
}
