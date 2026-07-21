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
//! TODO(M1): layout assertions + ctest wiring for one cell. TODO(M3): the §8.4
//! round-trip property. TODO(M2/M3): §8.5 closure check.
