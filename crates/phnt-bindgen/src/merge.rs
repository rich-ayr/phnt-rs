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

// ---------------------------------------------------------------------------
// Gate derivation (spec §4a up-set fold + fact 3 arch split). Collapses a
// variant's occurrence set into a compact, emittable predicate.
// ---------------------------------------------------------------------------

/// The captured matrix extent — every version ordinal / arch / surface that some
/// cell was generated for. Needed to tell "gated out" from "never captured": a
/// variant reaching the newest captured version is an **open** up-set `[min, ∞)`;
/// one that stops earlier was **superseded** by a later shape and is bounded.
#[derive(Clone, Debug, Default)]
pub struct CapturedAxis {
    pub versions: BTreeSet<u32>,
    pub arches: BTreeSet<Arch>,
    pub surfaces: BTreeSet<Surface>,
    /// The set of matrix coordinates actually generated. A cell is "captured" iff
    /// at least one item occurred in it (every real cell yields a non-empty
    /// module), so this is the union of every variant's occurrences — NOT the full
    /// `versions × arches × surfaces` product, which would invent sparse cells
    /// (e.g. a 32-bit kernel cell, or an uncaptured version×arch) that were never
    /// run and must not count as gate "phantoms".
    pub cells: BTreeSet<Occ>,
}

impl CapturedAxis {
    pub fn max_version(&self) -> Option<u32> {
        self.versions.iter().copied().next_back()
    }
}

/// A variant's emitted existence predicate, derived from its occurrences.
/// Version dimension is an ordinal interval `[min_ordinal, max_ordinal]`
/// (`max_ordinal = None` ⇒ open to ∞, the current shape); arch/surface dimensions
/// are explicit sets (→ `#[cfg(target_arch)]` / the `kernel` feature at emit).
/// `min_ordinal` is the **raw** minimum; the Win10-floor clamp (§4a) is an emit
/// concern exposed via [`Gate::emit_min_ordinal`], so this predicate stays exact
/// for every captured cell including sub-floor ones.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Gate {
    pub min_ordinal: u32,
    pub max_ordinal: Option<u32>,
    pub arches: BTreeSet<Arch>,
    pub surfaces: BTreeSet<Surface>,
}

impl Gate {
    /// Whether this gate admits cell `occ`.
    pub fn enables(&self, occ: Occ) -> bool {
        occ.ordinal >= self.min_ordinal
            && self.max_ordinal.is_none_or(|mx| occ.ordinal <= mx)
            && self.arches.contains(&occ.arch)
            && self.surfaces.contains(&occ.surface)
    }

    /// The version ordinal the gate emits at: raw min raised to the Win10 floor
    /// (spec §4a — sub-floor items collapse to the `win10` feature).
    pub fn emit_min_ordinal(&self) -> u32 {
        self.min_ordinal.max(crate::matrix::FLOOR_ORDINAL)
    }

    /// `true` if the gate spans every captured arch (⇒ no `target_arch` cfg needed).
    pub fn is_all_arch(&self, axis: &CapturedAxis) -> bool {
        self.arches == axis.arches
    }
}

/// Derive the compact [`Gate`] for an occurrence set. `max_ordinal` is left open
/// (`None`) when the variant reaches the newest captured version, else bounded to
/// its own last occurrence (a later shape-variant supersedes it above that).
pub fn derive_gate(occs: &BTreeSet<Occ>, axis: &CapturedAxis) -> Gate {
    let min_ordinal = occs.iter().map(|o| o.ordinal).min().unwrap_or(0);
    let max_occ = occs.iter().map(|o| o.ordinal).max().unwrap_or(0);
    let max_ordinal = if Some(max_occ) == axis.max_version() { None } else { Some(max_occ) };
    Gate {
        min_ordinal,
        max_ordinal,
        arches: occs.iter().map(|o| o.arch).collect(),
        surfaces: occs.iter().map(|o| o.surface).collect(),
    }
}

/// A variant whose occurrences do **not** form a clean version-interval × arch ×
/// surface rectangle, so its compact [`Gate`] would admit cells it never actually
/// occurred in (a version gap, or arch×version entanglement needing per-arch
/// ranges — spec fact 3 / M4). Reported, never silently emitted (spec §9).
#[derive(Clone, Debug)]
pub struct Irregular {
    pub key: Key,
    /// Cells the gate would admit but the variant never occurred in.
    pub phantom: BTreeSet<Occ>,
}

impl Merged {
    /// The captured extent, unioned over every variant's occurrences.
    pub fn axis(&self) -> CapturedAxis {
        let mut ax = CapturedAxis::default();
        let mut add = |occs: &BTreeSet<Occ>| {
            for &o in occs {
                ax.versions.insert(o.ordinal);
                ax.arches.insert(o.arch);
                ax.surfaces.insert(o.surface);
                ax.cells.insert(o);
            }
        };
        for v in self.records.values() {
            add(&v.occs);
        }
        for v in self.enums.values() {
            add(&v.occs);
        }
        for v in self.typedefs.values() {
            add(&v.occs);
        }
        for v in self.functions.values() {
            add(&v.occs);
        }
        ax
    }

    /// Every variant whose compact gate is **not** faithful to its occurrences
    /// (see [`Irregular`]). An empty result means every item is a clean rectangle
    /// that emit can gate losslessly. The `phantom` set is computed against the
    /// captured axis, so a gap only counts if that cell was actually generated.
    pub fn irregular_variants(&self, axis: &CapturedAxis) -> Vec<Irregular> {
        let mut out = Vec::new();
        let mut check = |key: &Key, occs: &BTreeSet<Occ>| {
            let gate = derive_gate(occs, axis);
            // A phantom is a genuinely-captured cell the gate admits but the
            // variant never occurred in — a version gap or arch×version
            // entanglement. Uncaptured coordinates are ignored (see `cells`).
            let phantom: BTreeSet<Occ> =
                axis.cells.iter().copied().filter(|o| gate.enables(*o) && !occs.contains(o)).collect();
            if !phantom.is_empty() {
                out.push(Irregular { key: key.clone(), phantom });
            }
        };
        for (k, v) in &self.records {
            check(k, &v.occs);
        }
        for (k, v) in &self.enums {
            check(k, &v.occs);
        }
        for (k, v) in &self.typedefs {
            check(k, &v.occs);
        }
        for (k, v) in &self.functions {
            check(k, &v.occs);
        }
        out
    }
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
                    doc: None,
                })
                .collect(),
            file: "synthetic.h".to_string(),
            anon: false,
            doc: None,
        }
    }

    fn tdef(name: &str, ty: CType) -> Typedef {
        Typedef { name: name.to_string(), ty, file: "synthetic.h".to_string(), doc: None }
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

    // --- gate derivation -------------------------------------------------------

    fn occ(ordinal: u32, arch: Arch) -> Occ {
        Occ { ordinal, arch, surface: Surface::User }
    }

    #[test]
    fn gate_open_upset_reaches_newest_version() {
        // A present unchanged at v100 and v114 (both captured, newest = 114).
        let a = rec("A", &[("f", CType::Prim(Prim::ULong))]);
        let merged = merge([
            (cell(100, Arch::X86_64), module(vec![a.clone()], vec![])),
            (cell(114, Arch::X86_64), module(vec![a.clone()], vec![])),
        ]);
        let axis = merged.axis();
        let g = derive_gate(&merged.records.values().next().unwrap().occs, &axis);
        assert_eq!(g.min_ordinal, 100);
        assert_eq!(g.max_ordinal, None, "reaches newest ⇒ open up-set");
        assert!(g.enables(occ(114, Arch::X86_64)));
        assert!(merged.irregular_variants(&axis).is_empty());
    }

    #[test]
    fn gate_bounded_when_superseded_by_later_shape() {
        // S is one shape at v100, a different shape at v114 (newest captured).
        let s_old = rec("S", &[("a", CType::Prim(Prim::ULong))]);
        let s_new = rec("S", &[("a", CType::Prim(Prim::ULong)), ("b", CType::Prim(Prim::ULong))]);
        let merged = merge([
            (cell(100, Arch::X86_64), module(vec![s_old.clone()], vec![])),
            (cell(114, Arch::X86_64), module(vec![s_new.clone()], vec![])),
        ]);
        let axis = merged.axis();
        for v in merged.records.values() {
            let g = derive_gate(&v.occs, &axis);
            match g.min_ordinal {
                100 => assert_eq!(g.max_ordinal, Some(100), "old shape bounded below newest"),
                114 => assert_eq!(g.max_ordinal, None, "current shape open"),
                other => panic!("unexpected min_ordinal {other}"),
            }
        }
        // Both variants are clean rectangles.
        assert!(merged.irregular_variants(&axis).is_empty());
    }

    #[test]
    fn irregular_flags_a_version_gap() {
        // A occurs at v100 and v114 but NOT v107 — yet v107 was captured (Z is
        // there). A's compact gate [100, ∞) would wrongly admit v107.
        let a = rec("A", &[("f", CType::Prim(Prim::ULong))]);
        let z = rec("Z", &[("g", CType::Prim(Prim::UShort))]);
        let merged = merge([
            (cell(100, Arch::X86_64), module(vec![a.clone(), z.clone()], vec![])),
            (cell(107, Arch::X86_64), module(vec![z.clone()], vec![])),
            (cell(114, Arch::X86_64), module(vec![a.clone(), z.clone()], vec![])),
        ]);
        let axis = merged.axis();
        let irr = merged.irregular_variants(&axis);
        assert_eq!(irr.len(), 1, "only A is irregular");
        assert_eq!(irr[0].key.name, "A");
        assert!(irr[0].phantom.contains(&occ(107, Arch::X86_64)));
    }

    #[test]
    fn emit_min_ordinal_clamps_to_win10_floor() {
        // A sub-floor variant (win7 = 61) collapses to the win10 feature at emit.
        let g = Gate {
            min_ordinal: 61,
            max_ordinal: None,
            arches: BTreeSet::from([Arch::X86_64]),
            surfaces: BTreeSet::from([Surface::User]),
        };
        assert_eq!(g.emit_min_ordinal(), crate::matrix::FLOOR_ORDINAL);
        assert_eq!(g.min_ordinal, 61, "raw min stays exact for round-trip");
    }
}
