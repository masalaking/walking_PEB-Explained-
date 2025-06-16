extern crate ntapi;
extern crate winapi;
use std::arch::asm;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr;
use winapi::shared::ntdef::UNICODE_STRING;
use ntapi::ntpebteb::{PEB, PPEB};
use ntapi::ntpsapi::PEB_LDR_DATA; 
use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};
use winapi::um::winnt::{IMAGE_DOS_SIGNATURE, LIST_ENTRY};

unsafe fn inline_assembly() -> *const PEB { //This is configured for Windows 64-bit, for a 32-bit the register should be the fs
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
    let mut module_base: *const LDR_DATA_TABLE_ENTRY = ptr::null();

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

             println!("MODULE NAME IS '{}'", module_name); //prints each module name after converting from UNICODE STRING to something rust can understand

            let trimmed_name = module_name.trim();
            if trimmed_name.eq_ignore_ascii_case("KERNEL32.DLL") {// optional functionality, for searching for a specific DLL to find a function
                println!("EXITING LOOP DLL FOUND");
                break 'outer;
            }
   
        }

        first_entry = unsafe { (*first_entry).Flink };
    }
    
    pe_file_parser(module_base);

}

unsafe fn pe_file_parser(module_base: *const LDR_DATA_TABLE_ENTRY) {

    let base = (*module_base).DllBase as *const u8;

    let dos_header = base as *const IMAGE_DOS_HEADER;
    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        println!("Invalid DOS signature");
        return;
    }

    let nt_headers_offset = (*dos_header).e_lfanew as usize;
    let nt_headers = base.add(nt_headers_offset) as *const IMAGE_NT_HEADERS;

    if (*nt_headers).Signature != 0x00004550 {
        println!("Invalid PE file signature");
        return;
    }

    let export_directory_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_directory_rva == 0 {
        println!("No export directory.");
        return;
    }

    let export_directory = base.add(export_directory_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let names_rva = (*export_directory).AddressOfNames;
    let functions_rva = (*export_directory).AddressOfFunctions;
    let ordinals_rva = (*export_directory).AddressOfNameOrdinals;
    let number_of_names = (*export_directory).NumberOfNames as usize;

    let names_ptr = base.add(names_rva as usize) as *const u32;
    let ordinals_ptr = base.add(ordinals_rva as usize) as *const u16;
    let addr_funcptr = base.add(functions_rva as usize) as *const u32;

    for i in 0..number_of_names {
        let name_rva = *names_ptr.add(i);
        let name_ptr = base.add(name_rva as usize) as *const u8;

        let mut length = 0;
        while *name_ptr.add(length) != 0 {
            length += 1;
        }

        let name_bytes = std::slice::from_raw_parts(name_ptr, length);
        let func_name = std::str::from_utf8(name_bytes).unwrap_or("<invalid utf8>");

        let ordinal_index = *ordinals_ptr.add(i) as usize;
        let func_rva = *addr_funcptr.add(ordinal_index);

        println!("Function {} at RVA 0x{:X}", func_name, func_rva);

        //let sleep_fn: extern "system" fn(u32) = std::mem::transmute(func_addr); To use a function from export table, take the func address and use the function, 
    }
}


fn main() {
    unsafe {
        peb_walker();
    }
}
