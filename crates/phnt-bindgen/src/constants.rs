//! Macro-constant extraction & evaluation (spec §5; §7 `constants`).
//!
//! phnt has many NTSTATUS / flag `#define`s, including non-literal expressions.
//! These must be evaluated *exactly*, not pattern-matched (spec §4 fact 5). The
//! approach (spec §6): `clang -dM -E` to enumerate object-like macros, then for
//! non-literal values compile-and-run a tiny probe that prints each value on the
//! matching-arch runner (no re-implementing the C expression grammar).
//!
//! TODO(M2): implement `-dM` extraction + probe-compile evaluation.
