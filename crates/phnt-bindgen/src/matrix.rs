//! Config matrix (spec §5, stage 1).
//!
//! Enumerates the `(version × arch × surface)` cells the generator runs clang
//! over. Versions are the axis that *requires* enumeration — the C preprocessor
//! consumes untaken `#if` branches, so a single parse only ever sees one
//! configuration. Arch runs catch structural `#ifdef _WIN64` divergence
//! (spec §4 fact 3); surface runs add the kernel (`Zw*`) file (spec §4c).

use std::fmt;

/// Target architecture. Drives the clang `--target` triple and, at emit time,
/// the `target_arch` / `target_pointer_width` cfgs for genuinely arch-structural
/// items (spec §5, fact 3).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Arch {
    /// `i686` — 32-bit. No kernel surface (Windows loads no 32-bit drivers).
    X86,
    /// `x86_64` — 64-bit.
    X86_64,
    /// `aarch64` — 64-bit ARM.
    Aarch64,
}

impl Arch {
    pub const ALL: [Arch; 3] = [Arch::X86_64, Arch::X86, Arch::Aarch64];

    /// The MSVC target triple passed to clang `--target=`.
    pub fn triple(self) -> &'static str {
        match self {
            Arch::X86 => "i686-pc-windows-msvc",
            Arch::X86_64 => "x86_64-pc-windows-msvc",
            Arch::Aarch64 => "aarch64-pc-windows-msvc",
        }
    }

    /// The Rust `target_arch` cfg value.
    pub fn rust_arch(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    pub fn pointer_width(self) -> u32 {
        match self {
            Arch::X86 => 32,
            Arch::X86_64 | Arch::Aarch64 => 64,
        }
    }

    /// Kernel drivers only load on 64-bit Windows (spec §4c, "Arch set").
    pub fn supports_kernel(self) -> bool {
        matches!(self, Arch::X86_64 | Arch::Aarch64)
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.rust_arch())
    }
}

/// Which API surface a cell parses. `Kernel` sets *both* the `PHNT_MODE` macro
/// and the `/KERNEL` codegen flag in the driver (spec §4c — one logical switch,
/// two clang args).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Surface {
    User,
    Kernel,
}

/// A phnt version threshold. These are the `PHNT_WINDOWS_*` ordinals from
/// `phnt.h` (NOT the spec's assumed hex `PHNT_WIN*`/`PHNT_THRESHOLD` — upstream
/// changed the scheme; see the project memory). Guards are monotone:
/// `#if (PHNT_VERSION >= PHNT_WINDOWS_<NAME>)`, so each item's existence set is
/// an up-set `[min, ∞)` keyed on `ordinal` (spec §4 fact 1).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Version {
    /// Upstream macro, e.g. `"PHNT_WINDOWS_10"`. Passed as `-DPHNT_VERSION=<ordinal>`.
    pub macro_name: &'static str,
    /// Ordinal value, e.g. `100`. The value used on the clang command line and
    /// the sort key for the up-set fold.
    pub ordinal: u32,
    /// Emitted Cargo feature slug, e.g. `"win10"`.
    pub feature: &'static str,
}

impl Version {
    pub fn define(self) -> String {
        format!("PHNT_VERSION={}", self.ordinal)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.feature, self.ordinal)
    }
}

/// The full ordered set of phnt version thresholds, ascending by ordinal.
/// Source of truth: `deps/phnt-nightly/phnt.h`. `ANCIENT` (0) and `NEW`
/// (`ULONG_MAX`) are intentionally omitted from the enumerated matrix — the
/// former predates every guard, the latter is the "unreleased" sentinel.
pub const VERSIONS: &[Version] = &[
    Version { macro_name: "PHNT_WINDOWS_XP",          ordinal: 51,  feature: "winxp" },
    Version { macro_name: "PHNT_WINDOWS_SERVER_2003", ordinal: 52,  feature: "ws03" },
    Version { macro_name: "PHNT_WINDOWS_VISTA",       ordinal: 60,  feature: "vista" },
    Version { macro_name: "PHNT_WINDOWS_7",           ordinal: 61,  feature: "win7" },
    Version { macro_name: "PHNT_WINDOWS_8",           ordinal: 62,  feature: "win8" },
    Version { macro_name: "PHNT_WINDOWS_8_1",         ordinal: 63,  feature: "win81" },
    Version { macro_name: "PHNT_WINDOWS_10",          ordinal: 100, feature: "win10" },
    Version { macro_name: "PHNT_WINDOWS_10_TH2",      ordinal: 101, feature: "win10_th2" },
    Version { macro_name: "PHNT_WINDOWS_10_RS1",      ordinal: 102, feature: "win10_rs1" },
    Version { macro_name: "PHNT_WINDOWS_10_RS2",      ordinal: 103, feature: "win10_rs2" },
    Version { macro_name: "PHNT_WINDOWS_10_RS3",      ordinal: 104, feature: "win10_rs3" },
    Version { macro_name: "PHNT_WINDOWS_10_RS4",      ordinal: 105, feature: "win10_rs4" },
    Version { macro_name: "PHNT_WINDOWS_10_RS5",      ordinal: 106, feature: "win10_rs5" },
    Version { macro_name: "PHNT_WINDOWS_10_19H1",     ordinal: 107, feature: "win10_19h1" },
    Version { macro_name: "PHNT_WINDOWS_10_19H2",     ordinal: 108, feature: "win10_19h2" },
    Version { macro_name: "PHNT_WINDOWS_10_20H1",     ordinal: 109, feature: "win10_20h1" },
    Version { macro_name: "PHNT_WINDOWS_10_20H2",     ordinal: 110, feature: "win10_20h2" },
    Version { macro_name: "PHNT_WINDOWS_10_21H1",     ordinal: 111, feature: "win10_21h1" },
    Version { macro_name: "PHNT_WINDOWS_10_21H2",     ordinal: 112, feature: "win10_21h2" },
    Version { macro_name: "PHNT_WINDOWS_10_22H2",     ordinal: 113, feature: "win10_22h2" },
    Version { macro_name: "PHNT_WINDOWS_11",          ordinal: 114, feature: "win11" },
    Version { macro_name: "PHNT_WINDOWS_11_22H2",     ordinal: 115, feature: "win11_22h2" },
    Version { macro_name: "PHNT_WINDOWS_11_23H2",     ordinal: 116, feature: "win11_23h2" },
    Version { macro_name: "PHNT_WINDOWS_11_24H2",     ordinal: 117, feature: "win11_24h2" },
    Version { macro_name: "PHNT_WINDOWS_11_25H2",     ordinal: 118, feature: "win11_25h2" },
    Version { macro_name: "PHNT_WINDOWS_11_26H1",     ordinal: 119, feature: "win11_26h1" },
    Version { macro_name: "PHNT_WINDOWS_11_27H2",     ordinal: 120, feature: "win11_27h2" },
];

/// The default emitted floor (spec §4a): `PHNT_WINDOWS_10`. Items below this
/// ordinal collapse to the `win10` gate unless the `legacy` feature is produced.
pub const FLOOR_ORDINAL: u32 = 100;

/// Look up a version by its `PHNT_WINDOWS_*` macro name or bare ordinal string.
pub fn lookup(name_or_ordinal: &str) -> Option<Version> {
    if let Ok(ord) = name_or_ordinal.parse::<u32>() {
        return VERSIONS.iter().copied().find(|v| v.ordinal == ord);
    }
    let want = name_or_ordinal.to_ascii_uppercase();
    VERSIONS.iter().copied().find(|v| {
        v.macro_name.eq_ignore_ascii_case(&want)
            || v.macro_name.eq_ignore_ascii_case(&format!("PHNT_WINDOWS_{want}"))
            || v.feature.eq_ignore_ascii_case(name_or_ordinal)
    })
}

/// The Win10 floor version (spec §4a). Convenience for single-cell milestones.
pub fn floor() -> Version {
    VERSIONS
        .iter()
        .copied()
        .find(|v| v.ordinal == FLOOR_ORDINAL)
        .expect("FLOOR_ORDINAL must exist in VERSIONS")
}

/// The Cargo feature slug for an ordinal, clamped up to the Win10 floor (spec
/// §4a — sub-floor items collapse to `win10`). An unrecognized ordinal falls back
/// to the floor feature. Used by `merge` to build `#[cfg(feature = …)]` gates.
pub fn feature_for_ordinal(ordinal: u32) -> &'static str {
    let clamped = ordinal.max(FLOOR_ORDINAL);
    VERSIONS
        .iter()
        .find(|v| v.ordinal == clamped)
        .map(|v| v.feature)
        .unwrap_or_else(|| floor().feature)
}

/// Render the Cargo `[features]` implication chain (spec §4a) for the emitted
/// crate. Every threshold at or above the Win10 floor enables the one below it, so
/// a consumer selects a single `winNN` feature and inherits every older gate via
/// the chain — which is exactly what lets a `cfg_predicate` open up-set carry only
/// its lower `feature = "winNN"` bound. Pre-Win10 thresholds form their own chain
/// gated behind an off-by-default `legacy` feature (tier-3 `win7` / `no_std`
/// audiences; §4a(2)). Deterministic text so regen diffs stay minimal.
pub fn feature_chain_toml() -> String {
    let mut out = String::from("[features]\n");
    out.push_str("default = [\"win10\"]\n\n");

    out.push_str("# Windows 10+ threshold chain (spec §4a): each release enables the previous,\n");
    out.push_str("# so selecting one feature inherits every older gate.\n");
    let mut prev: Option<&str> = None;
    for v in VERSIONS.iter().filter(|v| v.ordinal >= FLOOR_ORDINAL) {
        match prev {
            Some(p) => out.push_str(&format!("{} = [\"{}\"]\n", v.feature, p)),
            None => out.push_str(&format!("{} = []\n", v.feature)),
        }
        prev = Some(v.feature);
    }

    let sub_floor: Vec<&Version> = VERSIONS.iter().filter(|v| v.ordinal < FLOOR_ORDINAL).collect();
    if let Some(top) = sub_floor.last() {
        out.push('\n');
        out.push_str("# Pre-Win10 thresholds — opt-in via `legacy` (tier-3 win7 / no_std, §4a(2)).\n");
        out.push_str(&format!("legacy = [\"win10\", \"{}\"]\n", top.feature));
        let mut prev: Option<&str> = None;
        for v in &sub_floor {
            match prev {
                Some(p) => out.push_str(&format!("{} = [\"{}\"]\n", v.feature, p)),
                None => out.push_str(&format!("{} = []\n", v.feature)),
            }
            prev = Some(v.feature);
        }
    }
    out
}

/// One cell of the config matrix: a single clang invocation's worth of config.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Cell {
    pub version: Version,
    pub arch: Arch,
    pub surface: Surface,
}

impl Cell {
    pub fn new(version: Version, arch: Arch, surface: Surface) -> Self {
        Cell { version, arch, surface }
    }

    /// A stable, filesystem-safe label for cache/artifact naming.
    pub fn label(&self) -> String {
        let s = match self.surface {
            Surface::User => "user",
            Surface::Kernel => "kernel",
        };
        format!("{}-{}-{}", self.arch.rust_arch(), self.version.feature, s)
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_chain_links_each_release_to_the_previous() {
        let toml = feature_chain_toml();
        // Floor is the base of the chain (enables nothing).
        assert!(toml.contains("win10 = []"), "{toml}");
        // Win11 rides the chain through the last Win10 threshold, not straight to win10.
        assert!(toml.contains("win11 = [\"win10_22h2\"]"), "{toml}");
        assert!(toml.contains("win10_th2 = [\"win10\"]"), "{toml}");
        // Pre-floor gates are opt-in behind `legacy`, and chained among themselves.
        assert!(toml.contains("legacy = [\"win10\", \"win81\"]"), "{toml}");
        assert!(toml.contains("winxp = []"), "{toml}");
        assert!(toml.contains("win7 = [\"vista\"]"), "{toml}");
        // Every emitted version appears exactly once as a chain entry key.
        for v in VERSIONS {
            let key = format!("\n{} = [", v.feature);
            assert_eq!(toml.matches(&key).count(), 1, "feature {} not unique", v.feature);
        }
    }
}
