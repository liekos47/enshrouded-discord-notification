//! Generates the dbghelp.dll proxy: one jump stub per export of the system
//! dbghelp.dll, plus the linker arguments that export each stub under the
//! original name.

use std::{env, fmt::Write, fs, path::PathBuf};

fn main() {
    let system_root = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let dll = PathBuf::from(system_root).join("System32").join("dbghelp.dll");
    let names = export_names(&fs::read(&dll).expect("cannot read system dbghelp.dll"));

    let mut out = String::new();
    writeln!(out, "pub const COUNT: usize = {};", names.len()).unwrap();
    writeln!(out, "pub static NAMES: [&core::ffi::CStr; COUNT] = [").unwrap();
    for name in &names {
        writeln!(out, "    c\"{name}\",").unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out, "#[unsafe(no_mangle)]\npub static mut DW_FWD_TABLE: [usize; COUNT] = [0; COUNT];").unwrap();
    for (i, name) in names.iter().enumerate() {
        writeln!(
            out,
            "#[unsafe(naked)]\n#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn dw_fwd_{i}() {{\n    \
             core::arch::naked_asm!(\"jmp qword ptr [rip + {{t}} + {off}]\", t = sym DW_FWD_TABLE)\n}}",
            off = i * 8,
        )
        .unwrap();
        println!("cargo:rustc-cdylib-link-arg=/EXPORT:{name}=dw_fwd_{i}");
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("exports.rs"), out).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", dll.display());
}

fn export_names(pe: &[u8]) -> Vec<String> {
    let u16_at = |o: usize| u16::from_le_bytes(pe[o..o + 2].try_into().unwrap()) as usize;
    let u32_at = |o: usize| u32::from_le_bytes(pe[o..o + 4].try_into().unwrap()) as usize;

    let nt = u32_at(0x3c);
    let section_count = u16_at(nt + 6);
    let optional = nt + 24;
    let sections = optional + u16_at(nt + 20);
    let export_rva = u32_at(optional + 112);

    let offset = |rva: usize| {
        (0..section_count)
            .map(|i| sections + 40 * i)
            .find_map(|s| {
                let (va, raw_size, raw) = (u32_at(s + 12), u32_at(s + 16), u32_at(s + 20));
                (va <= rva && rva < va + raw_size).then(|| rva - va + raw)
            })
            .expect("rva outside every section")
    };

    let dir = offset(export_rva);
    let name_count = u32_at(dir + 24);
    let name_table = offset(u32_at(dir + 32));

    (0..name_count)
        .map(|i| {
            let start = offset(u32_at(name_table + 4 * i));
            let end = start + pe[start..].iter().position(|&b| b == 0).unwrap();
            String::from_utf8(pe[start..end].to_vec()).unwrap()
        })
        .collect()
}
