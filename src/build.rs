// MIT License
//
// Copyright (c) 2024 oberrich <oberrich.llvm@proton.me>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(dead_code)]

#[cfg_attr(docsrs, doc(cfg(feature = "regenerate")))]
#[cfg(feature = "regenerate")]
use regen::main;

#[cfg_attr(docsrs, doc(cfg(not(feature = "regenerate"))))]
#[cfg(not(feature = "regenerate"))]
fn main() {
   println!("Using vsendored bindings, build script skipped.");
}

#[cfg_attr(docsrs, doc(cfg(feature = "regenerate")))]
#[cfg(feature = "regenerate")]
mod regen {
   use regex::Regex;
   use std::collections::HashMap;
   use std::env;
   use std::path::PathBuf;

   use bindgen::callbacks::ParseCallbacks;

   #[derive(Debug)]
   struct ProcessComments;

   impl ParseCallbacks for ProcessComments {
      fn process_comment(&self, comment: &str) -> Option<String> {
         match doxygen_bindgen::transform(comment) {
            Ok(res) => Some(res),
            Err(err) => {
               println!("cargo:warning=Problem processing doxygen comment: {comment}\n{err}");
               None
            }
         }
      }
   }

   struct BindgenConfig {
      pub blocklist_types: Vec<String>,
      pub raw_lines: Vec<String>,
   }

   #[rustfmt::skip]
   impl Default for BindgenConfig {
      fn default() -> Self {
         let type_overrides: HashMap<_, _> = HashMap::from([
            ("NTSTATUS", "windows_sys::Win32::Foundation::NTSTATUS"),
            ("BOOL"    , "windows_sys::Win32::Foundation::BOOL"),
            ("BOOLEAN" , "windows_sys::Win32::Foundation::BOOLEAN"),
            ( "UNICODE_STRING", "nt_string::unicode_string::NtUnicodeString"),
            ("_UNICODE_STRING", "nt_string::unicode_string::NtUnicodeString"),
         ])
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();

         let blocklist_types = type_overrides.clone().into_keys().collect();
         let raw_lines = type_overrides
            .into_iter()
            .map(|(key, value)| format!("pub use {value} as {key};"))
            .collect();

         Self {
            blocklist_types,
            raw_lines,
         }
      }
   }

   impl BindgenConfig {
      pub fn new(blocklist_types: Vec<String>, raw_lines: Vec<String>) -> Self {
         Self {
            blocklist_types,
            raw_lines,
         }
      }

      pub fn generate_bindings(&self) -> Result<bindgen::Bindings, bindgen::BindgenError> {
         let allowlist_regexpr = Regex::new(&format!(
             r"({}\\deps\\phnt-nightly\\(?!ntzwapi\.h$)[^\\/]*\.h)|winnt\.h|ntstatus\.h",
             regex::escape(env!("CARGO_MANIFEST_DIR"))
         ))
         .unwrap();
         
         let blocklist_ty_regexpr =
            Regex::new(&format!(r"({})", self.blocklist_types.join("|"))).unwrap();

         let mut raw_lines = vec![
            format!("// Generated at {}", chrono::offset::Local::now()),
            format!(
               "#[cfg(not(target_arch = \"{}\"))]",
               std::env::var("CARGO_CFG_TARGET_ARCH").unwrap()
            ),
            format!(
               "compile_error!(\"These bindings can only be used on `{}` architectures. To generate bindings for your target architecture, consider using the `regenerate` feature.\");",
               std::env::var("CARGO_CFG_TARGET_ARCH").unwrap()
            ),
            "".into(),
         ];
         raw_lines.append(&mut self.raw_lines.clone());
         raw_lines.push(String::default());

         let mut clang_args: Vec<String> = vec![
            "-Iwindows.h".to_owned(),
            "-Iwinnt.h".to_owned(),
            concat!("-I", env!("CARGO_MANIFEST_DIR"), "\\deps\\phnt-nightly/").to_owned(),
         ];

         for name in ["PHNT_VERSION", "PHNT_MODE"] {
            println!("cargo:rerun-if-env-changed={}", name);
            if let Ok(str) = env::var(name) {
               clang_args.push(format!("-D{}={}", name, str));

               let value = if str.parse::<u32>().is_ok() {
                  str
               } else {
                  format!("self::{}", str)
               };

               raw_lines.push(format!("pub const {}: u32 = {};", name, value));
            }
         }

         bindgen::builder()
            .disable_header_comment()
            .header(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ffi/_wrapper.h"))
            .raw_line(raw_lines.join("\r\n").as_str())
            .clang_args(clang_args)
            .allowlist_file(allowlist_regexpr.as_str())
            .blocklist_type(blocklist_ty_regexpr.as_str())
            .type_alias("NTSTATUS")
            .opaque_type("std::.*")
            .use_core()
            .ctypes_prefix("crate::cty")
            .parse_callbacks(Box::new(ProcessComments))
            .default_enum_style(bindgen::EnumVariation::Rust {
               non_exhaustive: true,
            })
            .default_alias_style(bindgen::AliasVariation::TypeAlias)
            .default_macro_constant_type(bindgen::MacroTypeVariation::Unsigned)
            .default_non_copy_union_style(bindgen::NonCopyUnionStyle::ManuallyDrop)
            .translate_enum_integer_types(true)
            .derive_copy(true)
            .derive_default(true)
            .size_t_is_usize(true)
            .allowlist_recursively(true)
            .merge_extern_blocks(true)
            .generate_inline_functions(true)
            .vtable_generation(true)
            .generate_comments(true)
            .generate_block(true)
            .detect_include_paths(true)
            .prepend_enum_name(false)
            .block_extern_crate(false)
            .fit_macro_constants(false)
            .layout_tests(false)
            .emit_builtins()
            .enable_function_attribute_detection()
            .generate()
      }
   }

   pub fn main() {
      std::process::Command::new("git")
         .args(["submodule", "update", "--init", "--remote", "--recursive"])
         .output()
         .expect("phnt/build.rs: failed to update the `phnt-nightly` submodule!");

      println!(concat!(
         "cargo:rerun-if-changed=",
         env!("CARGO_MANIFEST_DIR"),
         "\\deps\\phnt-nightly"
      ));

      let out_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join(format!(
         "{}_bindgen.rs",
         std::env::var("CARGO_CFG_TARGET_ARCH").unwrap()
      ));

      BindgenConfig::default()
         .generate_bindings()
         .expect("Unable to generate bindings!")
         .write_to_file(out_path.clone())
         .expect("Unable to write bindings");

      println!("cargo:info=Wrote phnt bindings to `{}`", out_path.display());
   }
}
