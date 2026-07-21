//! `phnt-bindgen` CLI (spec §7 `xtask`/CLI).
//!
//! Wires the pipeline. Today it exposes `ast`, which reproduces the M0 driver
//! invocation and captures a JSON AST for one matrix cell — the concrete M0
//! deliverable ("a reproducible driver invocation + captured AST"). `generate`
//! / `regen` land in later milestones.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use phnt_bindgen::driver::Driver;
use phnt_bindgen::matrix::{self, Arch, Cell, Surface};

#[derive(Parser)]
#[command(name = "phnt-bindgen", about = "Faithful phnt FFI binding generator (replaces bindgen)")]
struct Cli {
    /// Workspace root containing `deps/phnt-nightly` and `src/ffi/_wrapper.h`.
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture a clang JSON AST for one matrix cell (M0 driver reproduction).
    Ast(AstArgs),
    /// Capture a clang record-layout dump for one matrix cell (verify ground truth).
    Layout(LayoutCmdArgs),
    /// Parse a JSON AST into the phnt IR and report a summary (M1 IR check).
    Parse(ParseArgs),
    /// Generate a self-contained Rust `ffi` source from a JSON AST (M1 emit).
    Generate(GenerateArgs),
    /// Merge multiple versions of one arch into one `#[cfg]`-gated `ffi` (§4a/§8.4).
    GenerateMerged(GenerateMergedArgs),
}

#[derive(clap::Args)]
struct GenerateMergedArgs {
    /// Versions to merge, ascending (repeat `--version` or comma-separate). Each
    /// resolves to `target/phnt-ast/<arch>-<feature>-user.json` (+ `.layouts.txt`).
    /// Defaults to the win10+win11 pair captured for the x64/user cell.
    #[arg(long = "version", value_delimiter = ',', default_values = ["win10", "win11"])]
    versions: Vec<String>,

    /// Target architecture — must match the captured cells (all share one arch).
    #[arg(long, value_enum, default_value_t = ArchArg::X64)]
    arch: ArchArg,

    /// Where to write the merged `.rs`. Defaults to `target/phnt-gen/ffi-merged.rs`.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Where to write the Cargo `[features]` chain (spec §4a). Defaults to
    /// `target/phnt-gen/features.toml`.
    #[arg(long)]
    features_out: Option<PathBuf>,

    /// Emit only the raw gated `ffi` with no layout-parity assertions.
    #[arg(long)]
    no_checks: bool,
}

#[derive(clap::Args)]
struct GenerateArgs {
    /// Path to a JSON AST. Defaults to the win10/x64 user artifact.
    #[arg(long)]
    ast: Option<PathBuf>,

    /// Where to write the generated `.rs`. Defaults to `target/phnt-gen/ffi.rs`.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Path to a clang record-layout dump (`phnt-bindgen layout`) for the *same*
    /// cell. When given, append `#[cfg(test)]` layout-parity assertions (spec §8
    /// check #2). Defaults to the cell's `target/phnt-ast/<cell>.layouts.txt` if it
    /// exists; pass `--no-checks` to skip.
    #[arg(long)]
    checks: Option<PathBuf>,

    /// Emit only the raw `ffi` with no layout-parity assertions.
    #[arg(long)]
    no_checks: bool,

    /// Target architecture of the AST/layout dump — sets the pointer width used
    /// for `#[repr]` and padding synthesis (x86 = 4 bytes, x64/arm64 = 8). Must
    /// match the cell the AST was captured for.
    #[arg(long, value_enum, default_value_t = ArchArg::X64)]
    arch: ArchArg,
}

#[derive(clap::Args)]
struct LayoutCmdArgs {
    /// Version threshold: a `PHNT_WINDOWS_*` name, a feature slug (`win10`), or a
    /// bare ordinal (`100`). Defaults to the Win10 floor.
    #[arg(long, default_value = "win10")]
    version: String,

    /// Target architecture.
    #[arg(long, value_enum, default_value_t = ArchArg::X64)]
    arch: ArchArg,

    /// Kernel surface (sets `PHNT_MODE=PHNT_MODE_KERNEL`; `/KERNEL` is TODO M6).
    #[arg(long)]
    kernel: bool,

    /// Where to write the layout dump. Defaults to `target/phnt-ast/<cell>.layouts.txt`.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Print the resolved clang command line and exit without running it.
    #[arg(long)]
    print_cmdline: bool,
}

#[derive(clap::Args)]
struct ParseArgs {
    /// Path to a JSON AST to parse. Defaults to the win10/x64 user artifact.
    #[arg(long)]
    ast: Option<PathBuf>,

    /// Print a few sample items per kind.
    #[arg(long)]
    sample: bool,
}

#[derive(clap::Args)]
struct AstArgs {
    /// Version threshold: a `PHNT_WINDOWS_*` name, a feature slug (`win10`), or a
    /// bare ordinal (`100`). Defaults to the Win10 floor.
    #[arg(long, default_value = "win10")]
    version: String,

    /// Target architecture.
    #[arg(long, value_enum, default_value_t = ArchArg::X64)]
    arch: ArchArg,

    /// Kernel surface (sets `PHNT_MODE=PHNT_MODE_KERNEL`; `/KERNEL` is TODO M6).
    #[arg(long)]
    kernel: bool,

    /// Where to write the JSON AST. Defaults to `target/phnt-ast/<cell>.json`.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Print the resolved clang command line and exit without running it.
    #[arg(long)]
    print_cmdline: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum ArchArg {
    X64,
    X86,
    Arm64,
}

impl From<ArchArg> for Arch {
    fn from(a: ArchArg) -> Self {
        match a {
            ArchArg::X64 => Arch::X86_64,
            ArchArg::X86 => Arch::X86,
            ArchArg::Arm64 => Arch::Aarch64,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = cli
        .root
        .canonicalize()
        .with_context(|| format!("resolving --root {}", cli.root.display()))?;

    match cli.cmd {
        Command::Ast(args) => run_ast(&root, args),
        Command::Layout(args) => run_layout(&root, args),
        Command::Parse(args) => run_parse(&root, args),
        Command::Generate(args) => run_generate(&root, args),
        Command::GenerateMerged(args) => run_generate_merged(&root, args),
    }
}

fn run_layout(root: &std::path::Path, args: LayoutCmdArgs) -> Result<()> {
    let version = matrix::lookup(&args.version)
        .with_context(|| format!("unknown --version `{}`", args.version))?;
    let arch: Arch = args.arch.into();
    let surface = if args.kernel { Surface::Kernel } else { Surface::User };

    if surface == Surface::Kernel && !arch.supports_kernel() {
        bail!("no kernel surface on {arch}: Windows loads no 32-bit kernel drivers (spec §4c)");
    }

    let cell = Cell::new(version, arch, surface);
    let driver = Driver::from_root(root);
    driver.preflight()?;

    let wrapper = driver.write_wrapper(&cell)?;

    if args.print_cmdline {
        println!("{}", driver.layout_cmdline(&cell, &wrapper));
        return Ok(());
    }

    let out = args
        .out
        .unwrap_or_else(|| driver.artifact_dir.join(format!("{}.layouts.txt", cell.label())));

    eprintln!("[phnt-bindgen] cell {cell}");
    eprintln!("[phnt-bindgen] $ {}", driver.layout_cmdline(&cell, &wrapper));
    driver.capture_layouts(&cell, &wrapper, &out)?;

    let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "[phnt-bindgen] wrote {} ({:.1} MiB)",
        out.display(),
        bytes as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}

fn run_generate(root: &std::path::Path, args: GenerateArgs) -> Result<()> {
    let ast = args
        .ast
        .unwrap_or_else(|| root.join("target").join("phnt-ast").join("x86_64-win10-user.json"));
    eprintln!("[phnt-bindgen] parsing {}", ast.display());
    let node = phnt_bindgen::ir::parse_ast(&ast)?;
    let m = phnt_bindgen::ir::lower(&node);
    let idx = phnt_bindgen::universe::build_index(&node);

    // Resolve the layout dump. It drives *both* faithful `#[repr]` selection
    // (packed / over-aligned records) and the parity assertions (spec §8 check #2).
    // Explicit `--checks` wins; otherwise fall back to the cell's default dump path
    // if present. `--no-checks` suppresses only the appended assertions — the reprs
    // are still corrected from the dump, since the AST lacks the pack/align values.
    let layout_path = args.checks.clone().or_else(|| {
        let default = ast.with_extension("layouts.txt");
        default.exists().then_some(default)
    });
    let layouts = match &layout_path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading layout dump {}", p.display()))?;
            eprintln!("[phnt-bindgen] layout dump {}", p.display());
            Some(phnt_bindgen::verify::parse_layouts(&text))
        }
        None => None,
    };

    let arch: Arch = args.arch.into();
    let ptr_bytes = (arch.pointer_width() / 8) as u64;
    let src = phnt_bindgen::emit::emit(&m, &idx, layouts.as_ref(), !args.no_checks, ptr_bytes)?;

    let out = args
        .out
        .unwrap_or_else(|| root.join("target").join("phnt-gen").join("ffi.rs"));
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out, &src)
        .with_context(|| format!("writing {}", out.display()))?;
    eprintln!(
        "[phnt-bindgen] wrote {} ({} lines, {:.1} KiB)",
        out.display(),
        src.lines().count(),
        src.len() as f64 / 1024.0
    );
    Ok(())
}

fn run_generate_merged(root: &std::path::Path, args: GenerateMergedArgs) -> Result<()> {
    let arch: Arch = args.arch.into();
    let ptr_bytes = (arch.pointer_width() / 8) as u64;
    let artifact_dir = root.join("target").join("phnt-ast");

    // Resolve each version to its captured AST (+ optional layout dump) by the
    // artifact naming convention. Ascending order makes the oldest cell the
    // representative for shared variants (least churn vs the single-cell output).
    let mut specs: Vec<phnt_bindgen::emit::CellSpec> = Vec::new();
    let mut versions: Vec<matrix::Version> = args
        .versions
        .iter()
        .map(|v| matrix::lookup(v).with_context(|| format!("unknown --version `{v}`")))
        .collect::<Result<_>>()?;
    versions.sort_by_key(|v| v.ordinal);
    versions.dedup_by_key(|v| v.ordinal);

    for version in versions {
        let cell = Cell::new(version, arch, Surface::User);
        let ast = artifact_dir.join(format!("{}.json", cell.label()));
        if !ast.exists() {
            bail!(
                "missing AST for {cell}: {}\n  capture it with: phnt-bindgen ast --version {} --arch {}",
                ast.display(),
                version.feature,
                arch.rust_arch(),
            );
        }
        let layout = ast.with_extension("layouts.txt");
        let layout_path = layout.exists().then_some(layout);
        specs.push(phnt_bindgen::emit::CellSpec { cell, ast_path: ast, layout_path, ptr_bytes });
    }

    eprintln!("[phnt-bindgen] merging {} cell(s) for {}", specs.len(), arch.rust_arch());
    let src = phnt_bindgen::emit::emit_merged(&specs, !args.no_checks)?;

    let out = args
        .out
        .unwrap_or_else(|| root.join("target").join("phnt-gen").join("ffi-merged.rs"));
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out, &src).with_context(|| format!("writing {}", out.display()))?;
    eprintln!(
        "[phnt-bindgen] wrote {} ({} lines, {:.1} KiB)",
        out.display(),
        src.lines().count(),
        src.len() as f64 / 1024.0
    );

    let features = args
        .features_out
        .unwrap_or_else(|| root.join("target").join("phnt-gen").join("features.toml"));
    std::fs::write(&features, matrix::feature_chain_toml())
        .with_context(|| format!("writing {}", features.display()))?;
    eprintln!("[phnt-bindgen] wrote feature chain {}", features.display());
    Ok(())
}

fn run_parse(root: &std::path::Path, args: ParseArgs) -> Result<()> {
    let ast = args
        .ast
        .unwrap_or_else(|| root.join("target").join("phnt-ast").join("x86_64-win10-user.json"));
    eprintln!("[phnt-bindgen] parsing {}", ast.display());

    let node = phnt_bindgen::ir::parse_ast(&ast)?;
    let m = phnt_bindgen::ir::lower(&node);

    println!("phnt IR summary for {}:", ast.display());
    println!("  records:        {}", m.records.len());
    println!("  enums:          {}", m.enums.len());
    println!("  typedefs:       {}", m.typedefs.len());
    println!("  functions:      {} (extern, linkable)", m.functions.len());
    println!("  inline helpers: {} (skipped from ffi; inventoried for ext)", m.inline_functions.len());
    println!("  total (surface):{}", m.total());

    // Anon hoisting + closure-resolution check (types are now pre-parsed CTypes).
    {
        use phnt_bindgen::ctype::CType;
        use phnt_bindgen::universe;
        use std::collections::BTreeSet;

        // Every field/param/typedef/return type should already be anon-resolved:
        // a residual `Anon` leaf means the parent-local hoisting missed one.
        fn residual_anon(t: &CType) -> bool {
            match t {
                CType::Anon(_) => true,
                CType::Pointer { inner, .. } | CType::Array { inner, .. } => residual_anon(inner),
                CType::FnPtr(fp) => residual_anon(&fp.ret) || fp.params.iter().any(residual_anon),
                _ => false,
            }
        }
        let hoisted = m.records.iter().filter(|r| r.anon).count();
        let mut residual = 0usize;
        let mut named_refs: BTreeSet<String> = BTreeSet::new();
        let collect = |t: &CType, residual: &mut usize, named: &mut BTreeSet<String>| {
            if residual_anon(t) {
                *residual += 1;
            }
            let mut refs = Vec::new();
            t.collect_refs(&mut refs);
            for r in refs {
                if !r.contains(".h:") && !r.contains(".c:") {
                    named.insert(r.to_string());
                }
            }
        };
        for r in &m.records {
            for f in &r.fields {
                collect(&f.ty, &mut residual, &mut named_refs);
            }
        }
        for t in &m.typedefs {
            collect(&t.ty, &mut residual, &mut named_refs);
        }
        for f in &m.functions {
            collect(&f.ret, &mut residual, &mut named_refs);
            for p in &f.params {
                collect(&p.ty, &mut residual, &mut named_refs);
            }
        }

        // Hoisted anon records carry synthetic names not present in the AST index;
        // they're resolved by the emitted records themselves.
        let synth: BTreeSet<&str> =
            m.records.iter().filter(|r| r.anon).filter_map(|r| r.name.as_deref()).collect();

        let idx = universe::build_index(&node);
        let resolves = |n: &str| {
            synth.contains(n)
                || idx.rec_by_name.contains_key(n)
                || idx.enum_by_name.contains_key(n)
                || idx.typedef_by_name.contains_key(n)
        };
        let unresolved_named: Vec<&String> = named_refs.iter().filter(|n| !resolves(n)).collect();

        println!(
            "  records incl. {hoisted} hoisted anon; {residual} residual unresolved anon leaves"
        );
        println!(
            "  universe: {} records, {} enums, {} typedefs by name",
            idx.rec_by_name.len(),
            idx.enum_by_name.len(),
            idx.typedef_by_name.len(),
        );
        println!(
            "  named refs: {} distinct, {} unresolved (opaque)",
            named_refs.len(),
            unresolved_named.len(),
        );
        if args.sample && !unresolved_named.is_empty() {
            println!("  -- unresolved named refs (opaque; first 20) --");
            for n in unresolved_named.iter().take(20) {
                println!("     {n}");
            }
        }
    }

    let cc_stdcall = m
        .functions
        .iter()
        .filter(|f| f.calling_conv == phnt_bindgen::ir::CallingConv::Stdcall)
        .count();
    println!("  (functions with stdcall CC: {cc_stdcall})");

    if args.sample {
        println!("\n-- sample records --");
        for r in m.records.iter().filter(|r| r.name.is_some()).take(4) {
            println!(
                "  {} ({}) [{} fields] @ {}",
                r.name.as_deref().unwrap_or("<anon>"),
                if r.is_union { "union" } else { "struct" },
                r.fields.len(),
                short_file(&r.file),
            );
        }
        println!("-- sample functions --");
        for f in m.functions.iter().take(4) {
            println!(
                "  {} [{} params, {:?}] @ {}",
                f.name,
                f.params.len(),
                f.calling_conv,
                short_file(&f.file),
            );
        }
        println!("-- sample hoisted anon records (parent-local, synthetic names) --");
        for r in m.records.iter().filter(|r| r.anon).take(4) {
            println!(
                "  {} ({}) [{} fields]:",
                r.name.as_deref().unwrap_or("?"),
                if r.is_union { "union" } else { "struct" },
                r.fields.len()
            );
            for f in r.fields.iter().take(4) {
                println!(
                    "      {}: {}{}",
                    f.name.as_deref().unwrap_or("(unnamed)"),
                    phnt_bindgen::ctype::render_debug(&f.ty),
                    f.bitfield_width.as_deref().map(|w| format!(" : {w}")).unwrap_or_default(),
                );
            }
        }
        println!("-- inline helpers by file (skipped from ffi; inventoried for ext) --");
        let mut by_file: std::collections::BTreeMap<String, usize> = Default::default();
        for f in &m.inline_functions {
            *by_file.entry(short_file(&f.file)).or_default() += 1;
        }
        for (file, n) in &by_file {
            println!("  {n:>4}  {file}");
        }
    }
    Ok(())
}

fn short_file(f: &str) -> String {
    f.replace('\\', "/").rsplit('/').next().unwrap_or(f).to_string()
}

fn run_ast(root: &std::path::Path, args: AstArgs) -> Result<()> {
    let version = matrix::lookup(&args.version)
        .with_context(|| format!("unknown --version `{}`", args.version))?;
    let arch: Arch = args.arch.into();
    let surface = if args.kernel { Surface::Kernel } else { Surface::User };

    if surface == Surface::Kernel && !arch.supports_kernel() {
        bail!("no kernel surface on {arch}: Windows loads no 32-bit kernel drivers (spec §4c)");
    }

    let cell = Cell::new(version, arch, surface);
    let driver = Driver::from_root(root);
    driver.preflight()?;

    // Synthesize the manifest-driven wrapper TU for this cell.
    let wrapper = driver.write_wrapper(&cell)?;

    if args.print_cmdline {
        println!("{}", driver.ast_cmdline(&cell, &wrapper));
        return Ok(());
    }

    let out = args
        .out
        .unwrap_or_else(|| driver.artifact_dir.join(format!("{}.json", cell.label())));

    eprintln!("[phnt-bindgen] cell {cell}");
    eprintln!("[phnt-bindgen] wrapper {}", wrapper.display());
    eprintln!("[phnt-bindgen] $ {}", driver.ast_cmdline(&cell, &wrapper));
    driver.capture_ast(&cell, &wrapper, &out)?;

    let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "[phnt-bindgen] wrote {} ({:.1} MiB)",
        out.display(),
        bytes as f64 / (1024.0 * 1024.0)
    );
    Ok(())
}
