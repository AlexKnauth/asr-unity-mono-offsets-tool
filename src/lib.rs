extern crate alloc;

mod binary_format;
mod file;
mod file_format;

use std::iter;

use asr::{
    future::{next_tick, retry},
    Process, file_format::pe, Address, Address32, signature::Signature, Address64, string::ArrayCString,
};

use binary_format::*;

use crate::{file::file_read_all_bytes, file_format::{elf, macho}};

use alloc::collections::{BTreeMap, BTreeSet};

asr::async_main!(stable);

// --------------------------------------------------------

const CSTR: usize = 128;

const PROCESS_NAMES: [&str; 7] = [
    "Hollow Knight",
    "hollow_knight",
    "hollow_knight.exe",
    "hollow_knight.x",
    "hollow_knight.x86_64",
    "SuperliminalSteam",
    "SuperliminalSteam.exe",
];

const MONO_NAMES: [&str; 6] = [
    "libmono.0.dylib",
    "libmono.so",
    "libmonobdwgc-2.0.dylib",
    "libmonobdwgc-2.0.so",
    "mono-2.0-bdwgc.dll",
    "mono.dll",
];

// --------------------------------------------------------

async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        asr::print_message(&panic_info.to_string());
    }));

    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let process = retry(|| {
            PROCESS_NAMES.into_iter().find_map(Process::attach)
        }).await;
        process
            .until_closes(async {
                match option_main(&process).await {
                    None => {
                        asr::print_message("option_main exit None");
                    },
                    Some(()) => {
                        asr::print_message("option_main exit Some(())");
                    }
                }
                loop {
                    next_tick().await;
                }
            })
            .await;
    }
}

async fn option_main(process: &Process) -> Option<()> {
    let format = process_detect_binary_format(&process)?;
    asr::print_message(&format!("binary format: {:?}", format));

    let Some((mono_name, mono_path, mono_range)) = MONO_NAMES.into_iter().find_map(|mono_name| {
        let mono_path = process.get_module_path(mono_name).ok()?;
        let mono_range = process.get_module_range(mono_name).ok()?;
        Some((mono_name, mono_path, mono_range))
    }) else {
        asr::print_message("BAD: failed to find mono");
        return None;
    };
    asr::print_message(&format!("mono_name: {}", mono_name));
    asr::print_message(&format!("mono_path: {}", mono_path));
    assert_eq!(path_detect_binary_format(&mono_path), Some(format));

    let deref_type = match format {
        BinaryFormat::PE => file_format::pe::detect_deref_type(process, mono_range)?,
        BinaryFormat::ELF => file_format::elf::detect_deref_type(process, mono_range)?,
        BinaryFormat::MachO => file_format::macho::detect_deref_type(process, mono_range)?,
    };
    asr::print_message(&format!("deref_type: {:?}", deref_type));

    let mono_assembly_foreach_address = match format {
        BinaryFormat::PE => {
            pe::symbols(process, mono_range.0)
                .find(|symbol| {
                    symbol
                        .get_name::<25>(process)
                        .is_ok_and(|name| name.matches("mono_assembly_foreach"))
                })?
                .address
        },
        BinaryFormat::ELF => {
            let mono_bytes = file_read_all_bytes(mono_path).ok()?;
            elf::get_function_address(process, mono_range, &mono_bytes, b"mono_assembly_foreach")?
        },
        BinaryFormat::MachO => {
            let mono_bytes = file_read_all_bytes(mono_path).ok()?;
            macho::get_function_address(process, mono_range, &mono_bytes, b"_mono_assembly_foreach")?
        }
    };
    asr::print_message(&format!("mono_assembly_foreach_address: {}", mono_assembly_foreach_address));

    let assemblies_pointer: Address = match (deref_type, format) {
        (DerefType::Bit64, BinaryFormat::PE) => {
            const SIG_MONO_64_PE: Signature<3> = Signature::new("48 8B 0D");
            let scan_address: Address = SIG_MONO_64_PE
                .scan_process_range(process, (mono_assembly_foreach_address, 0x100))?
                + 3;
            scan_address + 0x4 + process.read::<i32>(scan_address).ok()?
        },
        (DerefType::Bit64, BinaryFormat::ELF) => {
            const SIG_MONO_64_ELF: Signature<3> = Signature::new("48 8B 3D");
            // RIP-relative addressing
            // 3 is the offset to the next thing after the signature
            let scan_address = SIG_MONO_64_ELF.scan_process_range(process, (mono_assembly_foreach_address, 0x100))? + 3;
            // 4 is the offset to the next instruction after relative
            scan_address + 0x4 + process.read::<i32>(scan_address).ok()?
        },
        (DerefType::Bit64, BinaryFormat::MachO) => {
            const SIG_MONO_64_MACHO: Signature<3> = Signature::new("48 8B 3D");
            // RIP-relative addressing
            // 3 is the offset to the next thing after the signature
            let scan_address = SIG_MONO_64_MACHO.scan_process_range(process, (mono_assembly_foreach_address, 0x100))? + 3;
            // 4 is the offset to the next instruction after relative
            scan_address + 0x4 + process.read::<i32>(scan_address).ok()?
        },
        (DerefType::Bit32, BinaryFormat::PE) => {
            const SIG_32_1: Signature<2> = Signature::new("FF 35");
            const SIG_32_2: Signature<2> = Signature::new("8B 0D");

            let ptr = [SIG_32_1, SIG_32_2].iter().find_map(|sig| {
                sig.scan_process_range(process, (mono_assembly_foreach_address, 0x100))
            })? + 2;

            process.read::<Address32>(ptr + 2).ok()?.into()
        },
        (DerefType::Bit32, BinaryFormat::ELF) => { return None; },
        (DerefType::Bit32, BinaryFormat::MachO) => {
            return None;
        },
    };
    asr::print_message(&format!("assemblies_pointer: {}", assemblies_pointer));

    let assemblies: Address = read_pointer(process, deref_type, assemblies_pointer).ok()?;
    asr::print_message(&format!("assemblies: {}", assemblies));

    let first_assembly_data = read_pointer(process, deref_type, assemblies).ok()?;
    // asr::print_message(&format!("first_assembly_data: {}", first_assembly_data));

    let monoassembly_aname = [0x8, 0x10].into_iter().max_by_key(|&monoassembly_aname| {
        address_aname_score(process, deref_type, first_assembly_data + monoassembly_aname)
    })?;
    let aname_score = address_aname_score(process, deref_type, first_assembly_data + monoassembly_aname);
    asr::print_message(&format!("Offsets monoassembly_aname: 0x{:X?}, aname_score: {}", monoassembly_aname, aname_score));
    if aname_score < 5 {
        asr::print_message("BAD: aname_score is not at maximum");
    }
    if let Some(name_str) = monoassembly_aname_string(process, deref_type, first_assembly_data, monoassembly_aname) {
        asr::print_message(&format!("name_str: {}", name_str));
    }

    let default_assembly = assemblies_iter(process, deref_type, assemblies).find(|&assembly| {
        monoassembly_aname_string(process, deref_type, assembly, monoassembly_aname).as_deref() == Some("Assembly-CSharp")
    })?;
    // asr::print_message(&format!("default_assembly: {}", default_assembly));

    let monoassembly_image = [0x40, 0x44, 0x48, 0x58, 0x60].into_iter().max_by_key(|&monoassembly_image| {
        address_image_score(process, deref_type, default_assembly + monoassembly_image)
    })?;
    let image_score = address_image_score(process, deref_type, default_assembly + monoassembly_image);
    asr::print_message(&format!("Offsets monoassembly_image: 0x{:X?}, image_score: {}", monoassembly_image, image_score));
    if image_score < 5 {
        asr::print_message("BAD: image_score is not at maximum");
    }
    let default_image = read_pointer(process, deref_type, default_assembly + monoassembly_image).ok()?;
    // asr::print_message(&format!("default_image: {}", default_image));

    // Hard to guess both monoimage_class_cache and monointernalhashtable_size at the same time.
    // So make an assumption about monointernalhashtable_size based on 64-bit vs 32-bit.
    let monointernalhashtable_size = match deref_type {
        DerefType::Bit32 => 0xC,
        DerefType::Bit64 => 0x18,
    };
    asr::print_message(&format!("Offsets monointernalhashtable_size: 0x{:X?}, from {:?}", monointernalhashtable_size, deref_type));
    // Also make an assumption about monointernalhashtable_table based on 64-bit vs 32-bit.
    let monointernalhashtable_table = match deref_type {
        DerefType::Bit32 => 0x14,
        DerefType::Bit64 => 0x20,
    };
    asr::print_message(&format!("Offsets monointernalhashtable_table: 0x{:X?}, from {:?}", monointernalhashtable_table, deref_type));

    let monoimage_class_cache = [0x2A0, 0x354, 0x35C, 0x3D0, 0x4C0, 0x4D0].into_iter().max_by_key(|&monoimage_class_cache| {
        monoimage_class_cache_score(process, deref_type, default_image, monoimage_class_cache, monointernalhashtable_size, monointernalhashtable_table)
    })?;
    let class_cache_score = monoimage_class_cache_score(process, deref_type, default_image, monoimage_class_cache, monointernalhashtable_size, monointernalhashtable_table);
    asr::print_message(&format!("Offsets monoimage_class_cache: 0x{:X?}, class_cache_score: {}", monoimage_class_cache, class_cache_score));
    if class_cache_score < 8 {
        asr::print_message("BAD: class_cache_score is not at maximum");
    }
    let class_cache_size = process.read::<i32>(default_image + monoimage_class_cache + monointernalhashtable_size).ok()?;
    // asr::print_message(&format!("class_cache_size: {}", class_cache_size));
    let table_addr = read_pointer(process, deref_type, default_image + monoimage_class_cache + monointernalhashtable_table).ok()?;
    // asr::print_message(&format!("table_addr: {}", table_addr));
    let table = read_pointer(process, deref_type, table_addr).ok()?;
    // asr::print_message(&format!("table: {}", table));
    let class = read_pointer(process, deref_type, table).ok()?;
    // asr::print_message(&format!("class: {}", class));

    // Plan:
    //  * Find some class-related offsets first.
    //  * Then go back and find monoclassdef_next_class_cache,
    //    using the class-related offsets to score that.

    // Hard to guess both monoclassdef_klass and monoclass_name at the same time.
    // But monoclassdef_klass seems to always be 0 anyway.
    let monoclassdef_klass = 0x0;
    asr::print_message(&format!("Offsets monoclassdef_klass: 0x{:X?}, ASSUMED", monoclassdef_klass));
    let (monoclass_name, monoclass_name_space) = [(0x2C, 0x30), (0x30, 0x34), (0x38, 0x40), (0x40, 0x48), (0x48, 0x50)].into_iter().max_by_key(|&(monoclass_name, monoclass_name_space)| {
        monoclass_name_score(process, deref_type, class, monoclassdef_klass, monoclass_name, monoclass_name_space)
    })?;
    let class_name_score = monoclass_name_score(process, deref_type, class, monoclassdef_klass, monoclass_name, monoclass_name_space);
    asr::print_message(&format!("Offsets monoclass_name: 0x{:X?}, class_name_score: {}", monoclass_name, class_name_score));
    if class_name_score < 7 {
        asr::print_message("BAD: class_name_score is not at maximum");
    }
    

    let monoclassdef_next_class_cache = [0xA0, 0xA8, 0xF8, 0x100, 0x108].into_iter().max_by_key(|&monoclassdef_next_class_cache| {
        let next_class_cache_score = monoclassdef_next_class_cache_score(process, deref_type, table_addr, class_cache_size, monoclassdef_klass, monoclassdef_next_class_cache, monoclass_name, monoclass_name_space);
        // asr::print_message(&format!("monoclassdef_next_class_cache: 0x{:X?}, next_class_cache_score: {}", monoclassdef_next_class_cache, next_class_cache_score));
        next_class_cache_score
    })?;
    let next_class_cache_score = monoclassdef_next_class_cache_score(process, deref_type, table_addr, class_cache_size, monoclassdef_klass, monoclassdef_next_class_cache, monoclass_name, monoclass_name_space);
    asr::print_message(&format!("Offsets monoclassdef_next_class_cache: 0x{:X?}, next_class_cache_score: {}", monoclassdef_next_class_cache, next_class_cache_score));
    if next_class_cache_score < 12 {
        asr::print_message("BAD: next_class_cache_score is not at maximum");
    }

    let mscorlib_assembly = assemblies_iter(process, deref_type, assemblies).find(|&assembly| {
        monoassembly_aname_string(process, deref_type, assembly, monoassembly_aname).as_deref() == Some("mscorlib")
    })?;
    let mscorlib_image = read_pointer(process, deref_type, mscorlib_assembly + monoassembly_image).ok()?;
    let mscorlib_class_cache_size = process.read::<i32>(mscorlib_image + monoimage_class_cache + monointernalhashtable_size).ok()?;
    let mscorlib_table_addr = read_pointer(process, deref_type, mscorlib_image + monoimage_class_cache + monointernalhashtable_table).ok()?;

    // expect class_int32 to have 3 fields
    let map_name_field_counts: BTreeMap<&str, u32> = BTreeMap::from([
        ("Byte", 3),
        ("Guid", 15),
        ("Int32", 3),
        ("SByte", 3),
        ("UInt32", 3),
        ("UnSafeCharBuffer", 3),
    ]);
    let mut map_name_class_field_counts: BTreeMap<&str, (Address, u32)> = BTreeMap::new();
    for class in classes_iter(process, deref_type, mscorlib_table_addr, mscorlib_class_cache_size, monoclassdef_next_class_cache) {
        let Some(name) = class_name(process, deref_type, class, monoclassdef_klass, monoclass_name) else {
            break;
        };
        if let Some((&k, &v)) = map_name_field_counts.get_key_value(name.as_str()) {
            map_name_class_field_counts.insert(k, (class, v));
        }
    }

    let monoclassdef_field_count = [0x64, 0x8C, 0x94, 0x9C, 0xA4, 0xF0, 0xF8, 0x100].into_iter().max_by_key(|&monoclassdef_field_count| {
        let field_count_score: i32 = map_name_class_field_counts.values().map(|&(c, n)| {
            monoclassdef_field_count_score(process, deref_type, c, n, monoclassdef_field_count, monoclassdef_next_class_cache)
        }).sum();
        // asr::print_message(&format!("monoclassdef_field_count: 0x{:X?}, field_count_score: {}", monoclassdef_field_count, field_count_score));
        field_count_score
    })?;
    let field_count_score: i32 = map_name_class_field_counts.values().map(|&(c, n)| {
        monoclassdef_field_count_score(process, deref_type, c, n, monoclassdef_field_count, monoclassdef_next_class_cache)
    }).sum();
    asr::print_message(&format!("Offsets monoclassdef_field_count: 0x{:X?}, field_count_score: {}", monoclassdef_field_count, field_count_score));
    if field_count_score < 4 * map_name_class_field_counts.len() as i32 {
        asr::print_message("BAD: field_count_score is not at maximum");
    }

    // Hard to guess both monoclass_fields and monoclassfieldalignment at the same time.
    // So make an assumption about monoclassfieldalignment based on 64-bit vs 32-bit.
    let monoclassfieldalignment = match deref_type {
        DerefType::Bit32 => 0x10,
        DerefType::Bit64 => 0x20,
    };
    asr::print_message(&format!("Offsets monoclassfieldalignment: 0x{:X?}, from {:?}", monoclassfieldalignment, deref_type));
    // Also make an assumption about monoclassfield_name based on 64-bit vs 32-bit.
    let monoclassfield_name = match deref_type {
        DerefType::Bit32 => 0x4,
        DerefType::Bit64 => 0x8,
    };
    asr::print_message(&format!("Offsets monoclassfield_name: 0x{:X?}, from {:?}", monoclassfield_name, deref_type));
    // Also make an assumption about monoclassfield_offset based on 64-bit vs 32-bit.
    let monoclassfield_offset = match deref_type {
        DerefType::Bit32 => 0xC,
        DerefType::Bit64 => 0x18,
    };
    asr::print_message(&format!("Offsets monoclassfield_offset: 0x{:X?}, from {:?}", monoclassfield_offset, deref_type));

    let monoclass_fields = [0x60, 0x74, 0x90, 0x98, 0xA0, 0xA8].into_iter().max_by_key(|&monoclass_fields| {
        let fields_score: i32 = map_name_class_field_counts.values().map(|&(c, n1)| {
            let n2 = process.read::<u32>(c + monoclassdef_field_count).unwrap_or(n1);
            monoclass_fields_score(process, deref_type, c, n2, monoclassdef_klass, monoclass_fields, monoclassfieldalignment, monoclassfield_name)
        }).sum();
        // asr::print_message(&format!("monoclass_fields: 0x{:X?}, fields_score: {}", monoclass_fields, fields_score));
        fields_score
    })?;
    let fields_score: i32 = map_name_class_field_counts.values().map(|&(c, n1)| {
        let n2 = process.read::<u32>(c + monoclassdef_field_count).unwrap_or(n1);
        monoclass_fields_score(process, deref_type, c, n2, monoclassdef_klass, monoclass_fields, monoclassfieldalignment, monoclassfield_name)
    }).sum();
    asr::print_message(&format!("Offsets monoclass_fields: 0x{:X?}, fields_score: {}", monoclass_fields, fields_score));
    if fields_score < 5 * map_name_class_field_counts.len() as i32 {
        asr::print_message("BAD: fields_score is not at maximum");
    }

    let default_classes: BTreeSet<Address> = classes_iter(process, deref_type, table_addr, class_cache_size, monoclassdef_next_class_cache).collect();

    let monoclass_parent = [0x20, 0x24, 0x28, 0x30].into_iter().max_by_key(|&monoclass_parent| {
        let parent_score: i32 = default_classes.iter().map(|&c| {
            monoclass_parent_score(process, deref_type, c, monoclass_parent, monoclassdef_klass, monoclass_name)
        }).sum();
        // asr::print_message(&format!("monoclass_parent: 0x{:X?}, parent_score: {}", monoclass_parent, parent_score));
        parent_score
    })?;
    let parent_score: i32 = default_classes.iter().map(|&c| {
        monoclass_parent_score(process, deref_type, c, monoclass_parent, monoclassdef_klass, monoclass_name)
    }).sum();
    asr::print_message(&format!("Offsets monoclass_parent: 0x{:X?}, parent_score: {}", monoclass_parent, parent_score));
    if parent_score < 3 * default_classes.len() as i32 {
        asr::print_message(&format!("BAD BAD parent_score: some invalid classes, {} vs {}", parent_score, 3 * default_classes.len()));
    } else if parent_score == 3 * default_classes.len() as i32 {
        asr::print_message(&format!("BAD parent_score: they can't all be null, {} vs {}", parent_score, 3 * default_classes.len()));
    }

    // TODO get_static_table:
    //   monoclass_runtime_info
    //   monoclassruntimeinfo_domain_vtables
    //   monoclass_vtable_size
    //   monovtable_vtable

    // TODO: Load some initial information from the process.
    loop {
        // TODO: Do something on every tick.
        next_tick().await;
    }
}

fn read_pointer(process: &Process, deref_type: DerefType, address: Address) -> Result<Address, asr::Error> {
    Ok(match deref_type {
        DerefType::Bit64 => process.read::<Address64>(address)?.into(),
        DerefType::Bit32 => process.read::<Address32>(address)?.into(),
    })
}

fn address_aname_score(process: &Process, deref_type: DerefType, address: Address) -> i32 {
    let Ok(aname) = read_pointer(process, deref_type, address) else { return 0; };
    let Ok(name_cstr) = process.read::<ArrayCString<CSTR>>(aname) else { return 1; };
    let Ok(name_str) = std::str::from_utf8(&name_cstr) else { return 2; };
    if name_str.is_empty() { return 3; }
    if name_str.contains("/") || name_str.contains("\\") { return 4; }
    5
}

fn monoassembly_aname_string(process: &Process, deref_type: DerefType, address: Address, monoassembly_aname: i32) -> Option<String> {
    let address_aname = address + monoassembly_aname;
    let aname = read_pointer(process, deref_type, address_aname).ok()?;
    let name_cstr = process.read::<ArrayCString<CSTR>>(aname).ok()?;
    String::from_utf8(name_cstr.to_vec()).ok()
}

fn address_image_score(process: &Process, deref_type: DerefType, address: Address) -> i32 {
    let Ok(image) = read_pointer(process, deref_type, address) else { return 0;};
    if image.is_null() { return 1; }
    if image.value() < 0x10 { return 2; }
    if image.value() < 0x1000 { return 3; }
    if process.read::<u8>(image).is_err() { return 4; };
    5
}

fn monoimage_class_cache_score(
    process: &Process,
    deref_type: DerefType,
    image: Address,
    monoimage_class_cache: i32,
    monointernalhashtable_size: i32,
    monointernalhashtable_table: i32,
) -> i32 {
    let Ok(class_cache_size) = process.read::<i32>(image + monoimage_class_cache + monointernalhashtable_size) else {
        return 0;
    };
    if class_cache_size <= 0 { return 1; }
    if 0x10000 <= class_cache_size { return 2; }
    let Ok(table_addr) = read_pointer(process, deref_type, image + monoimage_class_cache + monointernalhashtable_table) else {
        return 3;
    };
    let Ok(table) = read_pointer(process, deref_type, table_addr) else {
        return 4;
    };
    let Ok(class) = read_pointer(process, deref_type, table) else {
        return 5;
    };
    if process.read::<u8>(class).is_err() { return 6; }
    if class != table { return 7; }
    8
}

fn monoclass_name_score(
    process: &Process,
    deref_type: DerefType,
    class: Address,
    monoclassdef_klass: i32,
    monoclass_name: i32,
    monoclass_name_space: i32,
) -> i32 {
    let Ok(name_ptr) = read_pointer(process, deref_type, class + monoclassdef_klass + monoclass_name) else {
        return 0;
    };
    let Ok(space_ptr) = read_pointer(process, deref_type, class + monoclassdef_klass + monoclass_name_space) else {
        return 1;
    };
    let Ok(name_cstr) = process.read::<ArrayCString<CSTR>>(name_ptr) else {
        return 2;
    };
    let Ok(space_cstr) = process.read::<ArrayCString<CSTR>>(space_ptr) else {
        return 3;
    };
    let Ok(name_str) = std::str::from_utf8(&name_cstr) else {
        asr::print_message(&format!("class name_cstr not utf8: {:X?}", name_cstr.as_bytes()));
        return 4;
    };
    if std::str::from_utf8(&space_cstr).is_err() { return 5; };
    if name_str.is_empty() { return 6; }
    // asr::print_message(&format!("class name_str: {}", name_str));
    // it's okay for the space to be an empty string,
    // but it's not okay for it to not be valid utf8
    7
}

fn class_name(process: &Process, deref_type: DerefType, class: Address, monoclassdef_klass: i32, monoclass_name: i32) -> Option<String> {
    let name_ptr = read_pointer(process, deref_type, class + monoclassdef_klass + monoclass_name).ok()?;
    let name_cstr = process.read::<ArrayCString<CSTR>>(name_ptr).ok()?;
    String::from_utf8(name_cstr.to_vec()).ok()
}

fn monoclassdef_next_class_cache_score(
    process: &Process,
    deref_type: DerefType,
    table_addr: Address,
    class_cache_size: i32,
    monoclassdef_klass: i32,
    monoclassdef_next_class_cache: i32,
    monoclass_name: i32,
    monoclass_name_space: i32,
) -> i32 {
    for i in 0..class_cache_size {
        let table_addr_i = table_addr + (i as u64).wrapping_mul(deref_type.size_of_ptr());
        let Ok(table1) = read_pointer(process, deref_type, table_addr_i) else {
            return 0;
        };
        let mut table = table1;
        let mut seen = BTreeSet::new();
        while !table.is_null() {
            if seen.replace(table).is_some() { return 11; }
            let Ok(class) = read_pointer(process, deref_type, table) else {
                return 1;
            };
            let class_score = monoclass_name_score(process, deref_type, class, monoclassdef_klass, monoclass_name, monoclass_name_space);
            if class_score < 7 { return 2 + class_score; }
            let Ok(table2) = read_pointer(process, deref_type, table + monoclassdef_next_class_cache) else {
                return 10;
            };
            table = table2;
        }
    }
    12
}

fn monoclassdef_field_count_score(
    process: &Process,
    _deref_type: DerefType,
    class: Address,
    expected: u32,
    monoclassdef_field_count: i32,
    monoclassdef_next_class_cache: i32,
) -> i32 {
    if monoclassdef_next_class_cache <= monoclassdef_field_count { return 0; }
    let Ok(field_count) = process.read::<u32>(class + monoclassdef_field_count) else {
        return 1;
    };
    if 0x100 <= field_count { return 2; }
    if field_count != expected { return 3; }
    // TODO: a better way of telling when something isn't the correct field count
    4
}

fn monoclass_fields_score(
    process: &Process,
    deref_type: DerefType,
    class: Address,
    n: u32,
    monoclassdef_klass: i32,
    monoclass_fields: i32,
    monoclassfieldalignment: i32,
    monoclassfield_name: i32
) -> i32 {
    let Ok(fields) = read_pointer(process, deref_type, class + monoclassdef_klass + monoclass_fields) else {
        return 0;
    };
    for i in 0..n {
        let field = fields + i.wrapping_mul(monoclassfieldalignment as u32);
        let Ok(name_addr) = read_pointer(process, deref_type, field + monoclassfield_name) else {
            return 1;
        };
        let Ok(name_cstr) = process.read::<ArrayCString<CSTR>>(name_addr) else {
            return 2;
        };
        let Ok(name_str) = std::str::from_utf8(&name_cstr) else { return 3; };
        if name_str.is_empty() { return 4; }
    }
    5
}

fn monoclass_parent_score(process: &Process, deref_type: DerefType, c: Address, monoclass_parent: i32, monoclassdef_klass: i32, monoclass_name: i32) -> i32 {
    let Ok(parent_addr) = read_pointer(process, deref_type, c + monoclassdef_klass + monoclass_parent) else {
        return 0;
    };
    // It's okay to be null, it's not okay to point to something not a valid class
    if parent_addr.is_null() {
        return 3;
    }
    let Ok(parent) = read_pointer(process, deref_type, parent_addr) else {
        return 1;
    };
    if class_name(process, deref_type, parent, monoclassdef_klass, monoclass_name).is_none() {
        return 2;
    }
    4
}

// --------------------------------------------------------

fn assemblies_iter<'a>(process: &'a Process, deref_type: DerefType, assemblies: Address) -> impl Iterator<Item = Address> + 'a {
    let mut assembly = assemblies;
    iter::from_fn(move || {
        if assembly.is_null() {
            None
        } else {
            let [data, next_assembly]: [Address; 2] = match deref_type {
                DerefType::Bit64 => process
                    .read::<[Address64; 2]>(assembly)
                    .ok()?
                    .map(|item| item.into()),
                DerefType::Bit32 => process
                    .read::<[Address32; 2]>(assembly)
                    .ok()?
                    .map(|item| item.into()),
            };
            assembly = next_assembly;
            Some(data)
        }
    })
}

fn classes_iter<'a>(
    process: &'a Process,
    deref_type: DerefType,
    table_addr: Address,
    class_cache_size: i32,
    monoclassdef_next_class_cache: i32,
) -> impl Iterator<Item = Address> + 'a {
    (0..class_cache_size).flat_map(move |i| {
        let table_addr_i = table_addr + (i as u64).wrapping_mul(deref_type.size_of_ptr());
        let mut table = read_pointer(process, deref_type, table_addr_i).unwrap_or_default();
        let mut seen = BTreeSet::new();
        iter::from_fn(move || -> Option<Address> {
            if table.is_null() || seen.replace(table).is_some() {
                None
            } else {
                let class = read_pointer(process, deref_type, table).ok()?;
                table = read_pointer(process, deref_type, table + monoclassdef_next_class_cache).unwrap_or_default();
                Some(class)
            }
        })
    })
}
