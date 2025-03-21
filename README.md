## [phnt][github.com]: Rust bindings to the [System Informer][github.com/sysinf]'s [phnt][github.com/sysinf/phnt]

[![phnt GitHub Actions][github.com/ci/img]][github.com/ci]
[![phnt on crates.io][shields.io/phnt]][crates.io]
[![phnt on crates.io][crates.io/img]][crates.io]
[![phnt on docs.rs][docs.rs/img]][docs.rs]

This crate provides Rust bindings to the **[System Informer][github.com/sysinf]**'s (formerly **Process Hacker**) [native Windows headers][github.com/sysinf/phnt] (**phnt**). These headers provide type definitions, constants, macros, and function prototypes, including support for undocumented Windows functions and syscalls.
### Getting Started
Add **phnt** to your `Cargo.toml`

```toml
[dependencies]
phnt = "x.y.z"  # Replace x.y.z with the latest version
```

### Features
| Feature | Description |
| --- | --- |
| _(default)_ | Uses **vendored** bindings for faster builds.                                                  |
| [`regenerate`][github.com/src/build.rs] | Allows regeneration of bindings from [phnt (nightly)][github.com/phnt_nightly] source code.   |
### Architectures
The following architectures are fully supported using **vendored** _(default)_ bindings
| Architecture  |  Description         |
|---------------|---------------------|
| `x86_64`    | Standard modern architecture for desktops and servers |
| `x86` _(i686)_| Legacy 32-bit architecture  |
| `aarch64` _(ARM64)_         | Modern 64-bit ARM architecture used in mobile and some desktops |

### Crate Overview
#### [`ffi`][docs.rs/ffi]
Low-level bindings generated from the [phnt (nightly)][github.com/phnt_nightly] source using [bindgen][crates.io/bindgen]
- [Re-exports][docs.rs/ffi/reexports]
- [Structs][docs.rs/ffi/structs]
- [Enums][docs.rs/ffi/enums]
- [Statics][docs.rs/ffi/statics]
- [Functions][docs.rs/ffi/functions]
- [Type Aliases][docs.rs/ffi/type-aliases]
- [Unions][docs.rs/ffi/unions]

#### [`ext`][docs.rs/ext]
Extensions to the bindings with additional utilities
- [Functions][docs.rs/ext/functions]
- [Macros][docs.rs/ext/macros]

[github.com]:               https://github.com/delulusoft/phnt-rs
[github.com/ci]:            https://github.com/delulusoft/phnt-rs/actions/workflows/rust.yml
[github.com/ci/img]:        https://github.com/delulusoft/phnt-rs/actions/workflows/rust.yml/badge.svg
[github.com/phnt_nightly]:  https://github.com/oberrich/phnt_nightly
[github.com/src/build.rs]:  https://github.com/delulusoft/phnt-rs/blob/master/src/build.rs
[github.com/sysinf]:        https://github.com/winsiderss/systeminformer
[github.com/sysinf/phnt]:   https://github.com/winsiderss/systeminformer/tree/master/phnt

[crates.io]:                https://crates.io/crates/phnt
[crates.io/bindgen]:        https://crates.io/crates/bindgen
[crates.io/img]:            https://img.shields.io/crates/v/phnt.svg
[shields.io/phnt]:          https://img.shields.io/crates/d/phnt.svg

[docs.rs]:                  https://docs.rs/phnt
[docs.rs/img]:              https://docs.rs/phnt/badge.svg
[docs.rs/ffi]:              https://docs.rs/phnt/latest/phnt/ffi/index.html
[docs.rs/ffi/reexports]:    https://docs.rs/phnt/latest/phnt/ffi/index.html#reexports
[docs.rs/ffi/structs]:      https://docs.rs/phnt/latest/phnt/ffi/index.html#structs
[docs.rs/ffi/enums]:        https://docs.rs/phnt/latest/phnt/ffi/index.html#enums
[docs.rs/ffi/constants]:    https://docs.rs/phnt/latest/phnt/ffi/index.html#constants
[docs.rs/ffi/statics]:      https://docs.rs/phnt/latest/phnt/ffi/index.html#statics
[docs.rs/ffi/functions]:    https://docs.rs/phnt/latest/phnt/ffi/index.html#functions
[docs.rs/ffi/type-aliases]: https://docs.rs/phnt/latest/phnt/ffi/index.html#types
[docs.rs/ffi/unions]:       https://docs.rs/phnt/latest/phnt/ffi/index.html#unions
[docs.rs/ext]:              https://docs.rs/phnt/latest/phnt/ext/index.html
[docs.rs/ext/functions]:    https://docs.rs/phnt/latest/phnt/ext/index.html#functions
[docs.rs/ext/macros]:       https://docs.rs/phnt/latest/phnt/index.html#macros
