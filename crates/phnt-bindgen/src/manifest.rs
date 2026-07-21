//! Per-file mode classification (spec §4b(1), §7 `manifest`).
//!
//! Every phnt header is tagged `user`, `kernel`, or `both`. The base surface
//! selects `user` + `both`; the `kernel` feature additionally pulls in `kernel`
//! files. This replaces bindgen's `.blocklist_file` regex workaround for
//! `ntzwapi.h` with principled, reviewable data (spec §4b, fact 6).
//!
//! NOTE: only `ntzwapi.h = kernel` is a *fixed* entry (spec §11.1). The rest
//! default to `both` pending a one-time classification pass against upstream,
//! re-checked on each nightly regen. Tightening these is tracked work, not a
//! blocker for the earlier milestones.

/// How a header participates in the two surfaces.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Mode {
    /// User-mode only.
    User,
    /// Kernel-mode only (behind the `kernel` feature). E.g. `ntzwapi.h`.
    Kernel,
    /// Present in both surfaces.
    Both,
}

/// A classified header (basename as it appears under `deps/phnt-nightly`).
#[derive(Copy, Clone, Debug)]
pub struct Entry {
    pub file: &'static str,
    pub mode: Mode,
}

/// The manifest. `ntzwapi.h` is the one fixed `kernel` entry (spec §4b(1));
/// everything else is provisionally `both` (see module note).
pub const ENTRIES: &[Entry] = &[
    Entry { file: "ntzwapi.h", mode: Mode::Kernel },
    // --- provisional `both`; review against upstream (spec §11.1) ---
    Entry { file: "ntafd.h",     mode: Mode::Both },
    Entry { file: "ntbcd.h",     mode: Mode::Both },
    Entry { file: "ntd3dkmt.h",  mode: Mode::Both },
    Entry { file: "ntdbg.h",     mode: Mode::Both },
    Entry { file: "ntexapi.h",   mode: Mode::Both },
    Entry { file: "ntgdi.h",     mode: Mode::Both },
    Entry { file: "ntimage.h",   mode: Mode::Both },
    Entry { file: "ntintsafe.h", mode: Mode::Both },
    Entry { file: "ntioapi.h",   mode: Mode::Both },
    Entry { file: "ntkeapi.h",   mode: Mode::Both },
    Entry { file: "ntldr.h",     mode: Mode::Both },
    Entry { file: "ntlpcapi.h",  mode: Mode::Both },
    Entry { file: "ntlsa.h",     mode: Mode::Both },
    Entry { file: "ntmisc.h",    mode: Mode::Both },
    Entry { file: "ntmmapi.h",   mode: Mode::Both },
    Entry { file: "ntnls.h",     mode: Mode::Both },
    Entry { file: "ntobapi.h",   mode: Mode::Both },
    Entry { file: "ntpebteb.h",  mode: Mode::Both },
    Entry { file: "ntpfapi.h",   mode: Mode::Both },
    Entry { file: "ntpnpapi.h",  mode: Mode::Both },
    Entry { file: "ntpoapi.h",   mode: Mode::Both },
    Entry { file: "ntpsapi.h",   mode: Mode::Both },
    Entry { file: "ntregapi.h",  mode: Mode::Both },
    Entry { file: "ntrtl.h",     mode: Mode::Both },
    Entry { file: "ntsam.h",     mode: Mode::Both },
    Entry { file: "ntseapi.h",   mode: Mode::Both },
    Entry { file: "ntsmss.h",    mode: Mode::Both },
    Entry { file: "ntstrsafe.h", mode: Mode::Both },
    Entry { file: "ntsxs.h",     mode: Mode::Both },
    Entry { file: "nttmapi.h",   mode: Mode::Both },
    Entry { file: "nttp.h",      mode: Mode::Both },
    Entry { file: "nttypesafe.h",mode: Mode::Both },
    Entry { file: "ntuser.h",    mode: Mode::Both },
    Entry { file: "ntwmi.h",     mode: Mode::Both },
    Entry { file: "ntwow64.h",   mode: Mode::Both },
    Entry { file: "ntxcapi.h",   mode: Mode::Both },
    // Non-`nt*`-prefixed headers + the phnt core headers (full set is 44 files).
    Entry { file: "smbios.h",         mode: Mode::Both },
    Entry { file: "subprocesstag.h",  mode: Mode::Both },
    Entry { file: "usermgr.h",        mode: Mode::Both },
    Entry { file: "winsta.h",         mode: Mode::Both },
    Entry { file: "phnt_ntdef.h",     mode: Mode::Both },
    Entry { file: "phnt_windows.h",   mode: Mode::Both },
    Entry { file: "phnt.h",           mode: Mode::Both },
];

/// Classify a header by basename. Unknown files default to `Both` so a newly
/// added upstream header is included (and surfaced by the nightly regen) rather
/// than silently dropped; the regen review re-checks the manifest (spec §9).
pub fn classify(basename: &str) -> Mode {
    ENTRIES
        .iter()
        .find(|e| e.file.eq_ignore_ascii_case(basename))
        .map(|e| e.mode)
        .unwrap_or(Mode::Both)
}
