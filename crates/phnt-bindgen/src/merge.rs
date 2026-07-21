//! Multi-config merge (spec §5, stage 4; §7 `merge`).
//!
//! The core of the project (spec §3). Keys every item by `(name,
//! definition_hash)`, folds each item's set of versions into a `min_version`
//! up-set (clamped to the Win10 floor, spec §4a), splits genuinely
//! arch-structural items onto `target_*` cfgs, and enforces the **gate-closure**
//! invariant `cfg(item) ⇒ cfg(referenced_type)` for every reference edge
//! (spec §4b(2)) — pulling types in or tightening gates, and failing generation
//! if closure cannot be satisfied.
//!
//! TODO(M3): up-set fold + feature chain. TODO(M2/M3): gate closure + the §8.5
//! dangling-reference check. TODO(M4): arch-structural split.
