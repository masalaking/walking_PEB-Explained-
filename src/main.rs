extern crate ntapi;
extern crate winapi;
use std::arch::asm;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::um::winnt::LIST_ENTRY;
use ntapi::ntpebteb::{PEB, PPEB};
use ntapi::ntpsapi::PEB_LDR_DATA; 
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};

unsafe fn inline_assembly() -> *const PEB { 
    let peb: *const PEB;
    asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb
    );
    peb
}

unsafe fn peb_walker() {
    let peb: PEB = *inline_assembly();
    let peb_ldr = peb.Ldr;
    let mut first_entry = (*peb_ldr).InMemoryOrderModuleList.Flink;
    let mut module_base: *const LDR_DATA_TABLE_ENTRY;

    let mut visited_modules = std::collections::HashSet::new();

    // Labeled break to exit outer loop when "KERNEL" is found
    'outer: while !first_entry.is_null() {
        if visited_modules.contains(&first_entry) {
            println!("repeat exiting ");
            break;
        }
        visited_modules.insert(first_entry);

        module_base = first_entry.byte_sub(0x10) as *const LDR_DATA_TABLE_ENTRY;
        let base_dll_name = &(*module_base).BaseDllName;

        if !base_dll_name.Buffer.is_null() {
            let mut length = 0;
            while *base_dll_name.Buffer.add(length) != 0x0000 {
                length += 1;
            }

             let name_bytes = std::slice::from_raw_parts(base_dll_name.Buffer as *const u16, length);
            let module_name = OsString::from_wide(name_bytes)
                .to_string_lossy()
                .into_owned();

             println!("MODULE NAME IS '{}'", module_name);

            let trimmed_name = module_name.trim();
            if trimmed_name.eq_ignore_ascii_case("KERNEL32.DLL") {
                println!("EXITING LOOP DLL FOUND");
                break 'outer;
            }
   
        }

        first_entry = unsafe { (*first_entry).Flink };
    }
    println!("NHSJS")
}

fn main() {
    unsafe {
        peb_walker();
    }
}
