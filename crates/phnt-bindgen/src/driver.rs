//! Clang driver (spec §5, stage 2; §7 `driver`).
//!
//! Owns *all* clang knowledge: how to synthesize the translation unit for a
//! matrix cell, build the argv, invoke clang, and capture its JSON AST (and,
//! later, the record-layout and macro dumps). Nothing else in the generator
//! shells out to clang.
//!
//! The primary mode is `-Xclang -ast-dump=json -fsyntax-only`, deserialized with
//! the `clang-ast` crate (spec §6). We do **not** parse `#if` expressions
//! ourselves — clang evaluates them; we vary `-DPHNT_VERSION` across cells and
//! read the difference (spec §5, stage 2).
//!
//! ## Wrapper synthesis
//!
//! phnt.h only pulls in ~31 of the 44 headers; the rest (`ntd3dkmt`, `winsta`,
//! `smbios`, `ntzwapi`, …) are standalone and must be `#include`d explicitly to
//! reach "the full phnt set". We therefore *synthesize* the TU from the manifest
//! rather than depend on the old bindgen `_wrapper.h`: the base/user surface
//! includes every non-`kernel` header; the kernel surface additionally includes
//! `kernel` headers (spec §3a — the manifest drives inclusion, no path regex).
//! Standalone headers empirically compile under user mode except `ntzwapi.h`
//! (kernel-only), verified 2026-07-21.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::manifest::{self, Mode};
use crate::matrix::{Cell, Surface};

/// Headers that are infrastructure/entry points, included explicitly and in a
/// specific order by the synthesized wrapper — excluded from the manifest-driven
/// include loop so they aren't re-included out of order.
const INFRA: &[&str] = &["phnt.h", "phnt_windows.h", "phnt_ntdef.h"];

/// Filesystem + tool configuration shared across all cells.
#[derive(Clone, Debug)]
pub struct Driver {
    /// The `clang` executable (name on `PATH`, or an absolute path). Override
    /// with `$PHNT_CLANG`.
    pub clang: PathBuf,
    /// Include root for the phnt headers, i.e. `<repo>/deps/phnt-nightly`.
    pub phnt_include: PathBuf,
    /// Directory synthesized wrappers and AST artifacts are written under.
    pub artifact_dir: PathBuf,
}

impl Driver {
    /// Build a driver rooted at the workspace root (the directory containing
    /// `deps/phnt-nightly`). Artifacts default to `<root>/target/phnt-ast`.
    pub fn from_root(root: &Path) -> Self {
        let clang = std::env::var_os("PHNT_CLANG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("clang"));
        Driver {
            clang,
            phnt_include: root.join("deps").join("phnt-nightly"),
            artifact_dir: root.join("target").join("phnt-ast"),
        }
    }

    /// Validate that the phnt include dir exists (the "first wall" is
    /// environment, spec §9).
    pub fn preflight(&self) -> Result<()> {
        if !self.phnt_include.is_dir() {
            bail!(
                "phnt include dir not found: {} (is the deps/phnt-nightly submodule checked out?)",
                self.phnt_include.display()
            );
        }
        Ok(())
    }

    /// The set of headers to `#include` for a cell's surface, in include order.
    /// Base/user: every non-`kernel`, non-infra header. Kernel: additionally the
    /// `kernel` headers. Infra headers are emitted by the fixed prefix instead.
    fn surface_headers(&self, surface: Surface) -> Vec<&'static str> {
        manifest::ENTRIES
            .iter()
            .filter(|e| !INFRA.contains(&e.file))
            .filter(|e| match (surface, e.mode) {
                // Kernel-only headers: only in the kernel surface.
                (Surface::User, Mode::Kernel) => false,
                (_, Mode::Kernel) => true,
                // user/both: always present (kernel surface is additive).
                _ => true,
            })
            .map(|e| e.file)
            .collect()
    }

    /// Synthesize the wrapper TU source for a cell. Mirrors the validated probe:
    /// pull the SDK via `phnt_windows.h`, then `phnt.h` (which pulls its ~31
    /// includes), then every remaining surface header. Re-includes are no-ops
    /// thanks to header guards; ordering after `phnt.h` satisfies the standalone
    /// headers' dependence on base phnt types.
    pub fn synthesize_wrapper(&self, cell: &Cell) -> String {
        let mut s = String::new();
        s.push_str("// Auto-synthesized by phnt-bindgen driver. Do not edit.\n");
        s.push_str(&format!("// cell: {}\n", cell.label()));
        s.push_str("#pragma once\n");
        // NTSTATUS values live behind WIN32_NO_STATUS in the SDK; undo it so both
        // <ntstatus.h> and <phnt_windows.h> agree (matches the old _wrapper.h).
        s.push_str("#undef WIN32_NO_STATUS\n");
        s.push_str("#include <ntstatus.h>\n");
        s.push_str("#include <phnt_windows.h>\n");
        s.push_str("#include <phnt.h>\n");
        for h in self.surface_headers(cell.surface) {
            s.push_str(&format!("#include <{h}>\n"));
        }
        s
    }

    /// Write the synthesized wrapper for `cell` to the artifact dir and return
    /// its path.
    pub fn write_wrapper(&self, cell: &Cell) -> Result<PathBuf> {
        std::fs::create_dir_all(&self.artifact_dir).ok();
        let path = self.artifact_dir.join(format!("{}.wrapper.h", cell.label()));
        let mut f = File::create(&path)
            .with_context(|| format!("creating wrapper {}", path.display()))?;
        f.write_all(self.synthesize_wrapper(cell).as_bytes())?;
        Ok(path)
    }

    /// The clang argv for a cell's JSON AST dump over `wrapper`. Mirrors the
    /// validated M0 invocation. `PHNT_MODE` is set explicitly for *both* surfaces
    /// so config is driver-owned (safe: phnt.h guards it with `#ifndef`); kernel
    /// cells add the two-signal kernel switch (spec §4c).
    pub fn ast_argv(&self, cell: &Cell, wrapper: &Path) -> Vec<OsString> {
        let mut argv: Vec<OsString> = Vec::new();
        let mut push = |s: &str| argv.push(OsString::from(s));

        push("-Xclang");
        push("-ast-dump=json");
        push("-fsyntax-only");

        push(&format!("--target={}", cell.arch.triple()));
        push("-fms-compatibility");
        push("-fms-extensions");

        push(&format!("-D{}", cell.version.define()));

        match cell.surface {
            Surface::User => push("-DPHNT_MODE=PHNT_MODE_USER"),
            Surface::Kernel => {
                push("-DPHNT_MODE=PHNT_MODE_KERNEL");
                // TODO(M6): thread the `/KERNEL` codegen flag (clang-cl `/kernel`
                // / clang-driver equivalent) here. AST-only syntax runs do not
                // need codegen, but faithful measurement (ctest, layout) does.
                // Setting the macro without the codegen flag is a latent bug
                // (spec §4c).
            }
        }

        push("-I");
        argv.push(self.phnt_include.clone().into_os_string());
        argv.push(wrapper.as_os_str().to_owned());
        argv
    }

    /// A copy-pasteable shell rendering of the AST invocation, for reproducibility
    /// (M0 deliverable: "a reproducible driver invocation").
    pub fn ast_cmdline(&self, cell: &Cell, wrapper: &Path) -> String {
        let mut parts = vec![self.clang.display().to_string()];
        for a in self.ast_argv(cell, wrapper) {
            parts.push(a.to_string_lossy().into_owned());
        }
        parts.join(" ")
    }

    /// Run clang for `cell` and stream its JSON AST to `out_json`. The AST for the
    /// full phnt surface is hundreds of MB, so we redirect straight to a file
    /// rather than buffering it in memory. Clang warnings go to `out_json`'s
    /// sibling `.stderr.txt`; a non-zero exit is a hard error.
    pub fn capture_ast(&self, cell: &Cell, wrapper: &Path, out_json: &Path) -> Result<()> {
        if let Some(parent) = out_json.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let out = File::create(out_json)
            .with_context(|| format!("creating AST output file {}", out_json.display()))?;
        let err_path = out_json.with_extension("stderr.txt");
        let err = File::create(&err_path)
            .with_context(|| format!("creating stderr file {}", err_path.display()))?;

        let status = Command::new(&self.clang)
            .args(self.ast_argv(cell, wrapper))
            .stdout(out)
            .stderr(err)
            .status()
            .with_context(|| format!("failed to spawn clang ({})", self.clang.display()))?;

        if !status.success() {
            bail!(
                "clang exited with {} for cell {}; see {}",
                status,
                cell,
                err_path.display()
            );
        }
        Ok(())
    }
}
