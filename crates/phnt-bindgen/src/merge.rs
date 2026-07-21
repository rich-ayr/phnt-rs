//! Multi-config merge (spec §5, stage 4; §7 `merge`).
//!
//! The core of the project (spec §3). Folds the per-cell IR modules captured
//! across the `(version × arch × surface)` matrix into a single set of items,
//! each keyed by `(name, definition_hash)` (spec §9 — same tag, different shape
//! across versions is real, so the name alone is not a key) and tagged with the
//! exact set of cells it occurred in ([`Occ`]). A later stage folds those
//! occurrences into an emitted gate (version up-set → `#[cfg(feature)]`, arch
//! split → `#[cfg(target_arch)]`, spec §4a/fact 3) under the gate-closure
//! invariant `cfg(item) ⇒ cfg(referenced_type)` (spec §4b(2)).
//!
//! ## Round-trip property (spec §8.4 — the primary regression net)
//! For each captured cell C, the items whose occurrence set contains C must be
//! exactly the items that cell's own module produced. This is a pure, in-memory
//! property (no clang, no toolchain) — it runs in `cargo test` on any host, so
//! merge logic is validated on the cheap cross-platform CI job while the heavy
//! per-cell clang capture stays in the Windows matrix job.
//!
//! TODO(next): up-set/range gate derivation (`min_ordinal`, arch/surface sets)
//! + gate-reproduces-cell test. TODO(M3): feature chain + gate closure (§4b/§8.5).

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{Enum, Function, Module, Record, Typedef};
use crate::matrix::{Arch, Cell, Surface};

/// Item namespace for the merge key — a record, enum, typedef, and function can
/// legitimately share a name, so the kind is part of the key.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Kind {
    Record,
    Enum,
    Typedef,
    Function,
}

/// The merge key: `(kind, tag name, definition-shape hash)`. Two entries with the
/// same `(kind, name)` but different `def_hash` are genuine shape-variants (a
/// struct whose layout changed between Windows versions) and stay separate so
/// they can be gated to disjoint version ranges (spec §9).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Key {
    pub kind: Kind,
    pub name: String,
    pub def_hash: u64,
}

/// One occurrence of an item: the matrix coordinates of a cell it appeared in.
/// `ordinal` is the version's `PHNT_WINDOWS_*` ordinal (not the macro name), so
/// occurrences sort by release age.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Occ {
    pub ordinal: u32,
    pub arch: Arch,
    pub surface: Surface,
}

/// A folded item: the representative decl (from the first cell it was seen in —
/// its shape is identical across all `occs` by construction of the hash) plus the
/// exact set of matrix cells it occurred in.
#[derive(Clone, Debug)]
pub struct MergedItem<T> {
    pub item: T,
    pub occs: BTreeSet<Occ>,
}

/// The merged universe: every distinct item variant, grouped by [`Key`], with its
/// occurrence set. Deterministic iteration order (`BTreeMap`) for stable output.
#[derive(Default)]
pub struct Merged {
    pub records: BTreeMap<Key, MergedItem<Record>>,
    pub enums: BTreeMap<Key, MergedItem<Enum>>,
    pub typedefs: BTreeMap<Key, MergedItem<Typedef>>,
    pub functions: BTreeMap<Key, MergedItem<Function>>,
}

impl Merged {
    /// Total distinct item variants across all kinds.
    pub fn len(&self) -> usize {
        self.records.len() + self.enums.len() + self.typedefs.len() + self.functions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every [`Key`] whose variant occurs in cell `occ` — i.e. the item set that
    /// filtering the merged universe down to that one cell yields. Used by the
    /// §8.4 round-trip property.
    pub fn keys_in(&self, occ: Occ) -> BTreeSet<Key> {
        let mut out = BTreeSet::new();
        let contains = |occs: &BTreeSet<Occ>| occs.contains(&occ);
        for (k, v) in &self.records {
            if contains(&v.occs) {
                out.insert(k.clone());
            }
        }
        for (k, v) in &self.enums {
            if contains(&v.occs) {
                out.insert(k.clone());
            }
        }
        for (k, v) in &self.typedefs {
            if contains(&v.occs) {
                out.insert(k.clone());
            }
        }
        for (k, v) in &self.functions {
            if contains(&v.occs) {
                out.insert(k.clone());
            }
        }
        out
    }
}

/// Fold per-cell modules into the merged universe. Each item is keyed by
/// `(kind, name, definition_hash)`; the first cell to contribute a key supplies
/// the representative decl, and every contributing cell is recorded in `occs`.
///
/// Only the emitted surface is merged (records/enums/typedefs/`functions`); the
/// skipped `inline_functions` inventory is not part of the ffi and is left out.
pub fn merge(cells: impl IntoIterator<Item = (Cell, Module)>) -> Merged {
    let mut m = Merged::default();
    for (cell, module) in cells {
        let occ = Occ { ordinal: cell.version.ordinal, arch: cell.arch, surface: cell.surface };
        for r in module.records {
            let key = Key {
                kind: Kind::Record,
                name: r.name.clone().unwrap_or_default(),
                def_hash: r.definition_hash(),
            };
            m.records
                .entry(key)
                .or_insert_with(|| MergedItem { item: r, occs: BTreeSet::new() })
                .occs
                .insert(occ);
        }
        for e in module.enums {
            let key = Key {
                kind: Kind::Enum,
                name: e.name.clone().unwrap_or_default(),
                def_hash: e.definition_hash(),
            };
            m.enums
                .entry(key)
                .or_insert_with(|| MergedItem { item: e, occs: BTreeSet::new() })
                .occs
                .insert(occ);
        }
        for t in module.typedefs {
            let key = Key {
                kind: Kind::Typedef,
                name: t.name.clone(),
                def_hash: t.definition_hash(),
            };
            m.typedefs
                .entry(key)
                .or_insert_with(|| MergedItem { item: t, occs: BTreeSet::new() })
                .occs
                .insert(occ);
        }
        for f in module.functions {
            let key = Key {
                kind: Kind::Function,
                name: f.name.clone(),
                def_hash: f.definition_hash(),
            };
            m.functions
                .entry(key)
                .or_insert_with(|| MergedItem { item: f, occs: BTreeSet::new() })
                .occs
                .insert(occ);
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctype::{CType, Prim};
    use crate::ir::{Field, Record, Typedef};
    use crate::matrix::{Arch, Surface, Version};

    // --- tiny synthetic-IR builders (no clang) ---------------------------------

    fn ver(ordinal: u32) -> Version {
        Version { macro_name: "PHNT_WINDOWS_X", ordinal, feature: "x" }
    }

    fn cell(ordinal: u32, arch: Arch) -> Cell {
        Cell::new(ver(ordinal), arch, Surface::User)
    }

    fn rec(name: &str, fields: &[(&str, CType)]) -> Record {
        Record {
            name: Some(name.to_string()),
            is_union: false,
            fields: fields
                .iter()
                .map(|(n, t)| Field {
                    name: Some(n.to_string()),
                    ty: t.clone(),
                    bitfield_width: None,
                })
                .collect(),
            file: "synthetic.h".to_string(),
            anon: false,
        }
    }

    fn tdef(name: &str, ty: CType) -> Typedef {
        Typedef { name: name.to_string(), ty, file: "synthetic.h".to_string() }
    }

    fn module(records: Vec<Record>, typedefs: Vec<Typedef>) -> Module {
        Module { records, typedefs, ..Module::default() }
    }

    /// The set of keys a raw module *would* contribute (its own item identities),
    /// for comparison against `Merged::keys_in`.
    fn own_keys(m: &Module) -> BTreeSet<Key> {
        let mut s = BTreeSet::new();
        for r in &m.records {
            s.insert(Key {
                kind: Kind::Record,
                name: r.name.clone().unwrap_or_default(),
                def_hash: r.definition_hash(),
            });
        }
        for t in &m.typedefs {
            s.insert(Key {
                kind: Kind::Typedef,
                name: t.name.clone(),
                def_hash: t.definition_hash(),
            });
        }
        s
    }

    #[test]
    fn definition_hash_distinguishes_shape_not_provenance() {
        // Same shape, different file/anon provenance ⇒ same hash.
        let a = rec("FOO", &[("x", CType::Prim(Prim::ULong))]);
        let mut b = a.clone();
        b.file = "other.h".into();
        b.anon = true;
        assert_eq!(a.definition_hash(), b.definition_hash());
        // Different field type ⇒ different hash.
        let c = rec("FOO", &[("x", CType::Prim(Prim::UShort))]);
        assert_ne!(a.definition_hash(), c.definition_hash());
    }

    #[test]
    fn round_trip_membership_is_exact() {
        // Two versions on one arch. v100 has {A, T}; v114 has {A (same shape), B}.
        let a = rec("A", &[("f", CType::Prim(Prim::ULong))]);
        let t = tdef("T", CType::Prim(Prim::ULong));
        let b = rec("B", &[("g", CType::Void)]);

        let m100 = module(vec![a.clone()], vec![t.clone()]);
        let m114 = module(vec![a.clone(), b.clone()], vec![]);

        let c100 = cell(100, Arch::X86_64);
        let c114 = cell(114, Arch::X86_64);
        let merged = merge([(c100, m100.clone()), (c114, m114.clone())]);

        // A is shared ⇒ one variant occurring in both cells; B/T each in one.
        assert_eq!(merged.records.len(), 2); // A, B
        assert_eq!(merged.typedefs.len(), 1); // T

        // §8.4: filtering the merged universe to each cell reproduces that cell.
        let occ100 = Occ { ordinal: 100, arch: Arch::X86_64, surface: Surface::User };
        let occ114 = Occ { ordinal: 114, arch: Arch::X86_64, surface: Surface::User };
        assert_eq!(merged.keys_in(occ100), own_keys(&m100));
        assert_eq!(merged.keys_in(occ114), own_keys(&m114));
    }

    #[test]
    fn same_name_different_shape_splits_into_two_variants() {
        // Struct S grows a field between v100 and v114 ⇒ two distinct variants,
        // each occurring only in its own version.
        let s_old = rec("S", &[("a", CType::Prim(Prim::ULong))]);
        let s_new = rec("S", &[("a", CType::Prim(Prim::ULong)), ("b", CType::Prim(Prim::ULong))]);

        let merged = merge([
            (cell(100, Arch::X86_64), module(vec![s_old.clone()], vec![])),
            (cell(114, Arch::X86_64), module(vec![s_new.clone()], vec![])),
        ]);

        assert_eq!(merged.records.len(), 2, "S must split into two shape-variants");
        // Each variant occurs in exactly one version.
        for v in merged.records.values() {
            assert_eq!(v.occs.len(), 1);
        }
    }

    #[test]
    fn shared_shape_across_arches_folds_but_records_both_occs() {
        // Identical struct on x64 and arm64, same version ⇒ one variant, two occs.
        let a = rec("A", &[("f", CType::Prim(Prim::ULong))]);
        let merged = merge([
            (cell(100, Arch::X86_64), module(vec![a.clone()], vec![])),
            (cell(100, Arch::Aarch64), module(vec![a.clone()], vec![])),
        ]);
        assert_eq!(merged.records.len(), 1);
        let occs = &merged.records.values().next().unwrap().occs;
        assert_eq!(occs.len(), 2);
        assert!(occs.iter().any(|o| o.arch == Arch::X86_64));
        assert!(occs.iter().any(|o| o.arch == Arch::Aarch64));
    }
}
