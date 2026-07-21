//! `phnt-bindgen` — a faithful, multi-configuration FFI binding generator for the
//! phnt native Windows headers.
//!
//! This crate replaces `bindgen` entirely (see `phnt-rs-generator-spec.md`). Its
//! reason to exist is *cross-configuration reasoning*: it drives clang over a
//! matrix of `(PHNT_VERSION × arch × surface)` cells and emits Rust from the
//! **difference** between configurations, so that version-gated items get a
//! corresponding `#[cfg(feature = ...)]`. `bindgen` is single-pass and cannot do
//! this (spec §3).
//!
//! Module layout mirrors spec §7. Pipeline: `matrix` → `driver` → `ir`
//! (+`constants`) → `merge` → `emit` → `verify`.

pub mod matrix;
pub mod manifest;
pub mod driver;
pub mod ir;
pub mod ctype;
pub mod universe;
pub mod constants;
pub mod merge;
pub mod emit;
pub mod verify;
