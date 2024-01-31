extern crate alloc;

mod binary_format;
mod file;
mod file_format;

use std::{cmp::max, iter};

use asr::{
    future::{next_tick, retry},
    Process, file_format::pe, Address, Address32, signature::Signature, Address64, string::ArrayCString, game_engine::unity::mono,
};

use binary_format::*;

use crate::{file::file_read_all_bytes, file_format::{elf, macho}};

use alloc::collections::{BTreeMap, BTreeSet};

asr::async_main!(stable);

// --------------------------------------------------------

const CSTR: usize = 128;

const PROCESS_NAMES: [&str; 8] = [
    "Clone Hero",
    "Hollow Knight",
    "hollow_knight",
    "hollow_knight.exe",
    "hollow_knight.x86_64",
    "hollow_knight.x",
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

const UNITY_PLAYER_NAMES: [&str; 3] = [
    "UnityPlayer.dll",
    "UnityPlayer.so",
    "UnityPlayer.dylib",
];

static EXCLUDE_PARENT_SCORE: [&str; 33] = [
    "Object",
    "IDisengageHandler",
    "InputControlSource",
    "ISpriteCollectionForceBuild",
    "IHitEffectReciever",
    "IInputControl",
    "IExternalDebris",
    "IExtraDamageable",
    "IHitResponder",
    "IVibrationMixerProvider",
    "BindingSourceListener",
    "ISharedData",
    "IUpdateable",
    "IBossStatueToggle",
    "IFsmCollider2DStateAction",
    "ITweenValue",
    "IMenuOptionLayout",
    "ITextElement",
    "IMenuOptionListSetting",
    "<Module>",
    "IKeyboardProvider",
    "IMouseProvider",
    "ISerializable",
    "IEnumerable",
    "IList",
    "IPointerClickHandler",
    "ICancelHandler",
    "ILayoutElement",
    "IEventSystemHandler",
    "IPointerExitHandler",
    "IDeselectHandler",
    "IFsmStateAction",
    "IDamageTaker",
];

// expect class_int32 to have 3 fields
const NAME_FIELD_COUNTS: [(&str, (u32, u32)); 6] = [
    ("Byte", (3, 25)),
    ("Guid", (15, 8)),
    ("Int32", (3, 25)),
    ("SByte", (3, 25)),
    ("UInt32", (3, 25)),
    ("UnSafeCharBuffer", (3, 4)),
];

const NAME_STATIC_FIELD_BYTES: [(&str, &[(&str, &[(&[(&str, &str)], &[u8])])]); 9] = [
    ("Boolean", &[
        ("TrueString", &[
            (&[("String", "m_stringLength")], &[0x04]),
            // (&[("String", "m_firstChar")], &[b'T']),
        ]),
        ("FalseString", &[
            (&[("String", "m_stringLength")], &[0x05]),
            // (&[("String", "m_firstChar")], &[b'F']),
        ]),
    ]),
    ("Char", &[
        ("categoryForLatin1", &[]),
    ]),
    ("DateTime", &[
        ("DaysToMonth365", &[]),
        ("DaysToMonth366", &[]),
        ("MinValue", &[]),
        ("MaxValue", &[]),
    ]),
    ("Enum", &[
        ("enumSeperatorCharArray", &[]),
    ]),
    ("IntPtr", &[
        ("Zero", &[]),
    ]),
    ("Math", &[
        ("doubleRoundLimit", &[]),
        ("roundPower10Double", &[]),
    ]),
    ("String", &[
        ("Empty", &[
            (&[("String", "m_stringLength")], &[0x00]),
        ]),
    ]),
    ("TimeSpan", &[
        ("Zero", &[]),
        ("MaxValue", &[]),
        ("MinValue", &[]),
    ]),
    /*
    ("TimeZone", &[
        ("currentTimeZone", &[]),
    ]),
    */
    ("Type", &[
        ("FilterAttribute", &[]),
        ("FilterName", &[]),
        ("FilterNameIgnoreCase", &[]),
        ("Missing", &[]),
        ("Delimiter", &[]),
        ("EmptyTypes", &[]),
        ("defaultBinder", &[]),
    ]),
];

// --------------------------------------------------------

async fn main() {
    std::panic::set_hook(Box::new(|panic_info| {
        asr::print_message(&panic_info.to_string());
    }));

    // TODO: Set up some general state and settings.

    asr::print_message("Hello, World!");

    loop {
        let (process, name) = retry(|| {
            PROCESS_NAMES.into_iter().find_map(|n| {
                Some((Process::attach(n)?, n))
            })
        }).await;
        process
            .until_closes(async {
                match option_main(&process, name).await {
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

async fn option_main(process: &Process, name: &str) -> Option<()> {
    let format = process_detect_binary_format(&process, name)?;
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
    assert_eq!(scan_page_detect_binary_format(process, mono_range), Some(format));

    let deref_type = match format {
        BinaryFormat::PE => file_format::pe::detect_deref_type(process, mono_range)?,
        BinaryFormat::ELF => file_format::elf::detect_deref_type(process, mono_range)?,
        BinaryFormat::MachO => file_format::macho::detect_deref_type(process, mono_range)?,
    };
    asr::print_message(&format!("deref_type: {:?}", deref_type));

    next_tick().await;

    let version = detect_version(process, mono_name)?;
    asr::print_message(&format!("version: {:?}", version));

    next_tick().await;

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
            elf::get_function_symbol_address(process, mono_range, &mono_bytes, b"mono_assembly_foreach")?
        },
        BinaryFormat::MachO => {
            let mono_bytes = file_read_all_bytes(mono_path).ok()?;
            macho::get_function_address(process, mono_range, &mono_bytes, b"_mono_assembly_foreach")?
        }
    };
    asr::print_message(&format!("mono_assembly_foreach_address: {}", mono_assembly_foreach_address));

    next_tick().await;

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

            process.read::<Address32>(ptr).ok()?.into()
        },
        (DerefType::Bit32, BinaryFormat::ELF) => { return None; },
        (DerefType::Bit32, BinaryFormat::MachO) => {
            return None;
        },
    };
    asr::print_message(&format!("assemblies_pointer: {}", assemblies_pointer));

    let assemblies: Address = read_pointer(process, deref_type, assemblies_pointer).ok()?;
    asr::print_message(&format!("assemblies: {}", assemblies));

    next_tick().await;

    let first_assembly_data = read_pointer(process, deref_type, assemblies).ok()?;
    // asr::print_message(&format!("first_assembly_data: {}", first_assembly_data));

    let monoassembly_aname = [0x8, 0x10].into_iter().max_by_key(|&monoassembly_aname| {
        address_aname_score(process, deref_type, first_assembly_data + monoassembly_aname)
    })?;
    let aname_score = address_aname_score(process, deref_type, first_assembly_data + monoassembly_aname);
    asr::print_message(&format!("Offsets monoassembly_aname: 0x{:X?}, aname_score: {} / 5", monoassembly_aname, aname_score));
    if aname_score < 5 {
        asr::print_message("BAD: aname_score is not at maximum");
    }
    if let Some(name_str) = monoassembly_aname_string(process, deref_type, first_assembly_data, monoassembly_aname) {
        asr::print_message(&format!("name_str: {}", name_str));
    }

    next_tick().await;

    let default_assembly = assemblies_iter(process, deref_type, assemblies).find(|&assembly| {
        monoassembly_aname_string(process, deref_type, assembly, monoassembly_aname).as_deref() == Some("Assembly-CSharp")
    })?;
    // asr::print_message(&format!("default_assembly: {}", default_assembly));

    let monoassembly_image = [0x40, 0x44, 0x48, 0x58, 0x60].into_iter().max_by_key(|&monoassembly_image| {
        address_image_score(process, deref_type, default_assembly + monoassembly_image)
    })?;
    let image_score = address_image_score(process, deref_type, default_assembly + monoassembly_image);
    asr::print_message(&format!("Offsets monoassembly_image: 0x{:X?}, image_score: {} / 5", monoassembly_image, image_score));
    if image_score < 5 {
        asr::print_message("BAD: image_score is not at maximum");
    }
    let default_image = read_pointer(process, deref_type, default_assembly + monoassembly_image).ok()?;
    // asr::print_message(&format!("default_image: {}", default_image));

    next_tick().await;

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

    next_tick().await;

    let monoimage_class_cache = [0x2A0, 0x354, 0x35C, 0x3D0, 0x4C0, 0x4D0].into_iter().max_by_key(|&monoimage_class_cache| {
        monoimage_class_cache_score(process, deref_type, default_image, monoimage_class_cache, monointernalhashtable_size, monointernalhashtable_table)
    })?;
    let class_cache_score = monoimage_class_cache_score(process, deref_type, default_image, monoimage_class_cache, monointernalhashtable_size, monointernalhashtable_table);
    asr::print_message(&format!("Offsets monoimage_class_cache: 0x{:X?}, class_cache_score: {} / 8", monoimage_class_cache, class_cache_score));
    if class_cache_score < 8 {
        asr::print_message("BAD: class_cache_score is not at maximum");
    }
    let class_cache_size = process.read::<i32>(default_image + monoimage_class_cache + monointernalhashtable_size).ok()?;
    // asr::print_message(&format!("class_cache_size: {}", class_cache_size));
    let table_addr = read_pointer(process, deref_type, default_image + monoimage_class_cache + monointernalhashtable_table).ok()?;
    // asr::print_message(&format!("table_addr: {}", table_addr));

    next_tick().await;

    // Plan:
    //  * Find some class-related offsets first.
    //  * Then go back and find monoclassdef_next_class_cache,
    //    using the class-related offsets to score that.

    let classes_no_next: BTreeSet<Address> = classes_no_next_iter(process, deref_type, table_addr, class_cache_size).collect();

    next_tick().await;

    // Hard to guess both monoclassdef_klass and other things at the same time.
    // But monoclassdef_klass seems to always be 0 anyway.
    let monoclassdef_klass = 0x0;
    asr::print_message(&format!("Offsets monoclassdef_klass: 0x{:X?}, ASSUMED", monoclassdef_klass));

    let monoclass_image = [0x28, 0x2C, 0x30, 0x38, 0x40].into_iter().max_by_key(|&monoclass_image| {
        let image_score: i32 = classes_no_next.iter().map(|&c| {
            monoclass_image_score(process, deref_type, c, monoclassdef_klass, monoclass_image, default_image)
        }).sum();
        // asr::print_message(&format!("monoclass_image: 0x{:X?}, image_score: {}", monoclass_image, image_score));
        image_score
    })?;
    let image_score: i32 = classes_no_next.iter().map(|&c| {
        monoclass_image_score(process, deref_type, c, monoclassdef_klass, monoclass_image, default_image)
    }).sum();
    asr::print_message(&format!("Offsets monoclass_image: 0x{:X?}, image_score: {} / {}", monoclass_image, image_score, 3 * classes_no_next.len()));
    if image_score < 3 * classes_no_next.len() as i32 {
        asr::print_message("BAD: image_score is not at maximum");
    }

    let (monoclass_name, monoclass_name_space) = [(0x2C, 0x30), (0x30, 0x34), (0x34, 0x38), (0x38, 0x40), (0x40, 0x48), (0x48, 0x50)].into_iter().max_by_key(|&(monoclass_name, monoclass_name_space)| {
        let class_name_score: i32 = classes_no_next.iter().map(|&c| {
            monoclass_name_score(process, deref_type, c, monoclassdef_klass, monoclass_name, monoclass_name_space)
        }).sum();
        // asr::print_message(&format!("monoclass_name: 0x{:X?} space: 0x{:X?}, class_name_score: {}", monoclass_name, monoclass_name_space, class_name_score));
        class_name_score
    })?;
    let class_name_score: i32 = classes_no_next.iter().map(|&c| {
        monoclass_name_score(process, deref_type, c, monoclassdef_klass, monoclass_name, monoclass_name_space)
    }).sum();
    asr::print_message(&format!("Offsets monoclass_name: 0x{:X?}, space: 0x{:X?}, class_name_score: {} / {}", monoclass_name, monoclass_name_space, class_name_score, 10 * classes_no_next.len()));
    if class_name_score < 10 * classes_no_next.len() as i32 {
        asr::print_message("BAD: class_name_score is not at maximum");
    }
    

    next_tick().await;

    let monoclassdef_next_class_cache = [0xA0, 0xA8, 0xAC, 0xF8, 0x100, 0x108].into_iter().max_by_key(|&monoclassdef_next_class_cache| {
        let next_class_cache_score = monoclassdef_next_class_cache_score(process, deref_type, table_addr, class_cache_size, monoclassdef_klass, monoclassdef_next_class_cache, monoclass_name, monoclass_name_space);
        // asr::print_message(&format!("monoclassdef_next_class_cache: 0x{:X?}, next_class_cache_score: {}", monoclassdef_next_class_cache, next_class_cache_score));
        next_class_cache_score
    })?;
    let next_class_cache_score = monoclassdef_next_class_cache_score(process, deref_type, table_addr, class_cache_size, monoclassdef_klass, monoclassdef_next_class_cache, monoclass_name, monoclass_name_space);
    asr::print_message(&format!("Offsets monoclassdef_next_class_cache: 0x{:X?}, next_class_cache_score: {} / 15", monoclassdef_next_class_cache, next_class_cache_score));
    if next_class_cache_score < 15 {
        asr::print_message("BAD: next_class_cache_score is not at maximum");
    }

    next_tick().await;

    let mscorlib_assembly = assemblies_iter(process, deref_type, assemblies).find(|&assembly| {
        monoassembly_aname_string(process, deref_type, assembly, monoassembly_aname).as_deref() == Some("mscorlib")
    })?;
    let mscorlib_image = read_pointer(process, deref_type, mscorlib_assembly + monoassembly_image).ok()?;
    let mscorlib_class_cache_size = process.read::<i32>(mscorlib_image + monoimage_class_cache + monointernalhashtable_size).ok()?;
    let mscorlib_table_addr = read_pointer(process, deref_type, mscorlib_image + monoimage_class_cache + monointernalhashtable_table).ok()?;

    next_tick().await;

    let map_name_class = classes_map(process, deref_type, mscorlib_table_addr, mscorlib_class_cache_size, monoclassdef_klass, monoclassdef_next_class_cache, monoclass_name);

    let map_name_field_counts: BTreeMap<&str, (u32, u32)> = BTreeMap::from(NAME_FIELD_COUNTS);
    let mut map_name_class_field_counts: BTreeMap<&str, (Address, u32, u32)> = BTreeMap::new();
    for (name, &class) in map_name_class.iter() {
        if let Some((&k, &(v1, v2))) = map_name_field_counts.get_key_value(name.as_str()) {
            map_name_class_field_counts.insert(k, (class, v1, v2));
        }
    }

    next_tick().await;

    let monoclassdef_field_count = [0x64, 0x68, 0x8C, 0x94, 0x9C, 0xA4, 0xF0, 0xF8, 0x100].into_iter().max_by_key(|&monoclassdef_field_count| {
        let field_count_score: i32 = map_name_class_field_counts.values().map(|&(c, n, _)| {
            monoclassdef_field_count_score(process, deref_type, c, n, monoclassdef_field_count, monoclassdef_next_class_cache)
        }).sum();
        // asr::print_message(&format!("monoclassdef_field_count: 0x{:X?}, field_count_score: {}", monoclassdef_field_count, field_count_score));
        field_count_score
    })?;
    let field_count_score: i32 = map_name_class_field_counts.values().map(|&(c, n, _)| {
        monoclassdef_field_count_score(process, deref_type, c, n, monoclassdef_field_count, monoclassdef_next_class_cache)
    }).sum();
    asr::print_message(&format!("Offsets monoclassdef_field_count: 0x{:X?}, field_count_score: {} / {}", monoclassdef_field_count, field_count_score, 4 * map_name_class_field_counts.len()));
    if field_count_score < 4 * map_name_class_field_counts.len() as i32 {
        asr::print_message("BAD: field_count_score is not at maximum");
    }

    next_tick().await;

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

    next_tick().await;

    let monoclass_fields = [0x60, 0x74, 0x78, 0x90, 0x98, 0xA0, 0xA8].into_iter().max_by_key(|&monoclass_fields| {
        let fields_score: i32 = map_name_class_field_counts.values().map(|&(c, n1, _)| {
            let n2 = process.read::<u32>(c + monoclassdef_field_count).unwrap_or(n1);
            monoclass_fields_score(process, deref_type, c, n2, monoclassdef_klass, monoclass_fields, monoclassfieldalignment, monoclassfield_name)
        }).sum();
        // asr::print_message(&format!("monoclass_fields: 0x{:X?}, fields_score: {}", monoclass_fields, fields_score));
        fields_score
    })?;
    let fields_score: i32 = map_name_class_field_counts.values().map(|&(c, n1, _)| {
        let n2 = process.read::<u32>(c + monoclassdef_field_count).unwrap_or(n1);
        monoclass_fields_score(process, deref_type, c, n2, monoclassdef_klass, monoclass_fields, monoclassfieldalignment, monoclassfield_name)
    }).sum();
    asr::print_message(&format!("Offsets monoclass_fields: 0x{:X?}, fields_score: {} / {}", monoclass_fields, fields_score, 5 * map_name_class_field_counts.len()));
    if fields_score < 5 * map_name_class_field_counts.len() as i32 {
        asr::print_message("BAD: fields_score is not at maximum");
    }

    next_tick().await;

    let default_classes: BTreeSet<Address> = classes_iter(process, deref_type, table_addr, class_cache_size, monoclassdef_next_class_cache).collect();

    next_tick().await;

    let parent_score_classes: BTreeSet<Address> = default_classes.iter().filter(|&&c| {
        let n = class_name(process, deref_type, c, monoclassdef_klass, monoclass_name).unwrap_or_default();
        !n.is_empty() && !EXCLUDE_PARENT_SCORE.contains(&n.as_str())
    }).cloned().collect();
    let monoclass_parent = [0x20, 0x24, 0x28, 0x30].into_iter().max_by_key(|&monoclass_parent| {
        let parent_score: i32 = parent_score_classes.iter().map(|&c| {
            monoclass_parent_score(process, deref_type, c, monoclass_parent, monoclassdef_klass, monoclass_name)
        }).sum();
        // asr::print_message(&format!("monoclass_parent: 0x{:X?}, parent_score: {}", monoclass_parent, parent_score));
        parent_score
    })?;
    let parent_score: i32 = parent_score_classes.iter().map(|&c| {
        monoclass_parent_score(process, deref_type, c, monoclass_parent, monoclassdef_klass, monoclass_name)
    }).sum();
    asr::print_message(&format!("Offsets monoclass_parent: 0x{:X?}, parent_score: {} / {}", monoclass_parent, parent_score, 4 * parent_score_classes.len()));
    if parent_score < 3 * parent_score_classes.len() as i32 {
        asr::print_message(&format!("BAD BAD parent_score: some invalid classes, {} vs {}", parent_score, 3 * parent_score_classes.len()));
    } else if parent_score == 3 * parent_score_classes.len() as i32 {
        asr::print_message(&format!("BAD parent_score: they can't all be null, {} vs {}", parent_score, 3 * parent_score_classes.len()));
    }

    next_tick().await;

    // Hard to guess both monoclass_runtime_info and monoclassruntimeinfo_domain_vtables at the same time.
    // So make an assumption about monoclassruntimeinfo_domain_vtables based on 64-bit vs 32-bit.
    let monoclassruntimeinfo_domain_vtables = match deref_type {
        DerefType::Bit32 => 0x4,
        DerefType::Bit64 => 0x8,
    };
    asr::print_message(&format!("Offsets monoclassruntimeinfo_domain_vtables: 0x{:X?}, from {:?}", monoclassruntimeinfo_domain_vtables, deref_type));

    next_tick().await;

    let map_name_static_field_bytes: BTreeMap<&str, &[(&str, &[(&[(&str, &str)], &[u8])])]> = BTreeMap::from(NAME_STATIC_FIELD_BYTES);
    let map_name_class_w_static: BTreeMap<&str, Address> = map_name_static_field_bytes.keys().filter_map(|&k| {
        Some((k, *map_name_class.get(&k.to_string())?))
    }).collect();

    let monoclass_runtime_info = [0x7C, 0x84, 0xA4, 0xA8, 0xC8, 0xD0, 0xF0, 0xF8].into_iter().max_by_key(|&monoclass_runtime_info| {
        let runtime_info_score: i32 = map_name_class_w_static.values().map(|&c| {
            monoclass_runtime_info_score(process, deref_type, c, monoclass_runtime_info, monoclassdef_klass, monoclassruntimeinfo_domain_vtables)
        }).sum();
        // asr::print_message(&format!("monoclass_runtime_info: 0x{:X?}, runtime_info_score: {}", monoclass_runtime_info, runtime_info_score));
        runtime_info_score
    })?;
    let runtime_info_score: i32 = map_name_class_w_static.values().map(|&c| {
        monoclass_runtime_info_score(process, deref_type, c, monoclass_runtime_info, monoclassdef_klass, monoclassruntimeinfo_domain_vtables)
    }).sum();
    asr::print_message(&format!("Offsets monoclass_runtime_info: 0x{:X?}, runtime_info_score: {} / {}", monoclass_runtime_info, runtime_info_score, 6 * map_name_class_w_static.len()));
    if runtime_info_score < 6 * map_name_class_w_static.len() as i32 {
        asr::print_message(&format!("BAD runtime_info_score: {} vs {}", runtime_info_score, 6 * map_name_class_w_static.len()));
    }

    next_tick().await;

    // TODO get_static_table:
    //   monoclass_runtime_info
    //   monoclass_vtable_size
    //   monovtable_vtable

    // monovtable_vtable is NOT used for V1, only for V2 and V3,
    // and monoclass_vtable_size is used completely differently,
    // so from here on it forks into 2 branches
    if version == mono::Version::V1 {
        asr::print_message("UNUSED / UNCONSTRAINED monovtable_vtable");
        static_table_offsets_v1(deref_type).await?;
    } else {
        static_table_offsets_v2_v3(
            process,
            deref_type,
            version,
            map_name_class,
            map_name_class_field_counts,
            monoclassdef_klass,
            monoclassdef_field_count,
            monoclass_fields,
            monoclassfieldalignment,
            monoclassfield_name,
            monoclassfield_offset,
            monoclass_runtime_info,
            monoclassruntimeinfo_domain_vtables,
        ).await?;
    }

    // TODO: Load some initial information from the process.
    loop {
        // TODO: Do something on every tick.
        next_tick().await;
    }
}

async fn static_table_offsets_v1(deref_type: DerefType) -> Option<()> {
    // this V1 monoclass_vtable_size is actually MonoVtable.data
    let monoclass_vtable_size = match deref_type {
        DerefType::Bit32 => 0xC,
        DerefType::Bit64 => 0x18,
    };
    asr::print_message(&format!("V1 Offsets monoclass_vtable_size (MonoVtable.data): 0x{:X?}, from {:?}", monoclass_vtable_size, deref_type));
    Some(())
}

async fn static_table_offsets_v2_v3(
    process: &Process,
    deref_type: DerefType,
    version: mono::Version,
    map_name_class: BTreeMap<String, Address>,
    map_name_class_field_counts: BTreeMap<&str, (Address, u32, u32)>,
    monoclassdef_klass: i32,
    monoclassdef_field_count: i32,
    monoclass_fields: i32,
    monoclassfieldalignment: i32,
    monoclassfield_name: i32,
    monoclassfield_offset: i32,
    monoclass_runtime_info: i32,
    monoclassruntimeinfo_domain_vtables: i32,
) -> Option<()> {
    // this V2/V3 monoclass_vtable_size is actually TypeDefinitionVTableSize
    let monoclass_vtable_size = [0x38, 0x54, 0x5C].into_iter().max_by_key(|&monoclass_vtable_size| {
        let vtable_size_score: i32 = map_name_class_field_counts.values().map(|&(c, _, n)| {
            v2_v3_monoclass_vtable_size_score(process, monoclassdef_klass, monoclass_vtable_size, c, n)
        }).sum();
        // asr::print_message(&format!("{:?} monoclass_vtable_size (TypeDefinitionVTableSize): 0x{:X}, vtable_size_score: {}", version, monoclass_vtable_size, vtable_size_score));
        vtable_size_score
    })?;
    asr::print_message(&format!("{:?} Offsets monoclass_vtable_size (TypeDefinitionVTableSize): 0x{:X}", version, monoclass_vtable_size));
    let vtable_size_score: i32 = map_name_class_field_counts.values().map(|&(c, _, n)| {
        v2_v3_monoclass_vtable_size_score(process, monoclassdef_klass, monoclass_vtable_size, c, n)
    }).sum();
    if vtable_size_score < 5 * map_name_class_field_counts.len() as i32 {
        asr::print_message("BAD: vtable_size_score is not at maximum");
    }

    /*
    TimeSpan: MaxValue: 0x8  = new TimeSpan(Int64.MaxValue)
    TimeSpan: MinValue: 0x10 = new TimeSpan(Int64.MinValue)
    */

    let monovtable_vtable = [0x28, 0x2C, 0x40, 0x48].into_iter().max_by_key(|&monovtable_vtable| {
        let vtable_score: i32 = v2_v3_monovtable_vtable_score(
            process,
            deref_type,
            &map_name_class,
            monoclassdef_klass,
            monoclassdef_field_count,
            monoclass_fields,
            monoclassfieldalignment,
            monoclassfield_name,
            monoclassfield_offset,
            monoclass_runtime_info,
            monoclassruntimeinfo_domain_vtables,
            monoclass_vtable_size,
            monovtable_vtable
        ).unwrap_or_default();
        // asr::print_message(&format!("{:?} monovtable_vtable: 0x{:X}, vtable_score: {}", version, monovtable_vtable, vtable_score));
        vtable_score
    })?;
    let vtable_score: i32 = v2_v3_monovtable_vtable_score(
        process,
        deref_type,
        &map_name_class,
        monoclassdef_klass,
        monoclassdef_field_count,
        monoclass_fields,
        monoclassfieldalignment,
        monoclassfield_name,
        monoclassfield_offset,
        monoclass_runtime_info,
        monoclassruntimeinfo_domain_vtables,
        monoclass_vtable_size,
        monovtable_vtable
    ).unwrap_or_default();
    asr::print_message(&format!("{:?} Offsets monovtable_vtable: 0x{:X}, vtable_score: {} / 4", version, monovtable_vtable, vtable_score));
    if vtable_score < 4 {
        asr::print_message("BAD: vtable_score is not at maximum");
    }
    Some(())
}

fn read_pointer(process: &Process, deref_type: DerefType, address: Address) -> Result<Address, asr::Error> {
    Ok(match deref_type {
        DerefType::Bit64 => process.read::<Address64>(address)?.into(),
        DerefType::Bit32 => process.read::<Address32>(address)?.into(),
    })
}

fn detect_version(process: &Process, mono_name: &str) -> Option<mono::Version> {
    if ["libmono.0.dylib", "libmono.so", "mono.dll"].contains(&mono_name) {
        return Some(mono::Version::V1);
    }

    let unity_range = UNITY_PLAYER_NAMES.into_iter().find_map(|name| {
        process.get_module_range(name).ok()
    })?;

    // null "202" wildcard "."
    const SIG_202X: Signature<6> = Signature::new("00 32 30 32 ?? 2E");

    let Some(addr) = SIG_202X.scan_process_range(process, unity_range) else {
        return Some(mono::Version::V2);
    };

    let version_string = process.read::<[u8; 6]>(addr + 1).ok()?;

    let (before, after) = version_string.split_at(version_string.iter().position(|&x| x == b'.')?);

    let unity: u32 = ascii_read_u32(before);

    let unity_minor: u32 = ascii_read_u32(&after[1..]);
    
    Some(if (unity == 2021 && unity_minor >= 2) || (unity > 2021) {
        mono::Version::V3
    } else {
        mono::Version::V2
    })
}

fn ascii_read_u32(slice: &[u8]) -> u32 {
    const ZERO: u8 = b'0';
    const NINE: u8 = b'9';

    let mut result: u32 = 0;
    for &val in slice {
        match val {
            ZERO..=NINE => result = result * 10 + (val - ZERO) as u32,
            _ => break,
        }
    }
    result
}

// --------------------------------------------------------

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

fn monoclass_image_score(
    process: &Process,
    deref_type: DerefType,
    class: Address,
    monoclassdef_klass: i32,
    monoclass_image: i32,
    image: Address,
) -> i32 {
    let Ok(c_image) = read_pointer(process, deref_type, class + monoclassdef_klass + monoclass_image) else {
        return 0;
    };
    if !process.read::<u8>(c_image).is_ok() {
        return 1;
    }
    if c_image != image {
        // asr::print_message(&format!("c_image {} != image {}", c_image, image));
        return 2;
    }
    3
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
        // asr::print_message(&format!("class name_cstr not utf8: {:X?}", name_cstr.as_bytes()));
        return 4;
    };
    let Ok(space_str) = std::str::from_utf8(&space_cstr) else {
        // asr::print_message(&format!("class space_cstr not utf8: {:X?}", space_cstr.as_bytes()));
        return 5;
    };
    if !name_str.chars().all(|c| c.is_ascii_graphic()) { return 6; }
    if !space_str.chars().all(|c| c.is_ascii_graphic()) { return 7; }
    if name_str.is_empty() { return 8; }
    if space_str.is_empty() {
        // asr::print_message(&format!("space empty for {}", name_str));
        // return 9;
    }
    // asr::print_message(&format!("class name_str: {}, space_str: {}", name_str, space_str));
    // it's okay for the space to be an empty string,
    // but it's not okay for it to not be valid utf8
    10
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
    let mut m = 0;
    // let mut s = 0;
    for i in 0..class_cache_size {
        let table_addr_i = table_addr + (i as u64).wrapping_mul(deref_type.size_of_ptr());
        let Ok(table1) = read_pointer(process, deref_type, table_addr_i) else {
            return 0;
        };
        let mut table = table1;
        let mut seen = BTreeSet::new();
        let mut n_i = 0;
        while !table.is_null() {
            if seen.replace(table).is_some() { return 11; }
            let Ok(class) = read_pointer(process, deref_type, table) else {
                return 1;
            };
            let class_score = monoclass_name_score(process, deref_type, class, monoclassdef_klass, monoclass_name, monoclass_name_space);
            if class_score < 9 { return 2 + class_score; }
            let Ok(table2) = read_pointer(process, deref_type, table + monoclassdef_next_class_cache) else {
                return 13;
            };
            table = table2;
            n_i += 1;
        }
        m = max(m, n_i);
        // s += n_i;
    }
    // asr::print_message(&format!("monoclassdef_next_class_cache_score: m = {}, s = {}", m, s));
    15 + m
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
    // let name = class_name(process, deref_type, c, monoclassdef_klass, monoclass_name);
    let Ok(parent_addr) = read_pointer(process, deref_type, c + monoclassdef_klass + monoclass_parent) else {
        // asr::print_message(&format!("monoclass_parent_score reading monoclass_parent fails: {:?}", name));
        return 0;
    };
    // It's okay to be null, it's not okay to point to something not a valid class
    if parent_addr.is_null() {
        // asr::print_message(&format!("monoclass_parent_score name null: {:?}", name));
        return 3;
    }
    let Ok(parent) = read_pointer(process, deref_type, parent_addr) else {
        // asr::print_message(&format!("monoclass_parent_score parent_addr problem for: {:?}", name));
        return 1;
    };
    if class_name(process, deref_type, parent, monoclassdef_klass, monoclass_name).is_none() {
        // asr::print_message(&format!("monoclass_parent_score parent name problem for parent of: {:?}", name));
        return 2;
    }
    4
}

fn monoclass_runtime_info_score(process: &Process, deref_type: DerefType, c: Address, monoclass_runtime_info: i32, monoclassdef_klass: i32, monoclassruntimeinfo_domain_vtables: i32) -> i32 {
    let Ok(runtime_info) = read_pointer(process, deref_type, c + monoclassdef_klass + monoclass_runtime_info) else {
        return 0;
    };
    // It's okay to be null?
    if runtime_info.is_null() {
        return 5;
    }
    let Ok(max_domain) = process.read::<u16>(runtime_info) else {
        return 1;
    };
    if 0x1000 <= max_domain { return 2; }
    // asr::print_message(&format!("0x{:X?} max_domain {}", monoclass_runtime_info, max_domain));
    let Ok(vtables) = read_pointer(process, deref_type, runtime_info + monoclassruntimeinfo_domain_vtables) else {
        return 3;
    };
    if process.read::<u8>(vtables).is_err() {
        return 4;
    }
    6
}

fn v2_v3_monoclass_vtable_size_score(
    process: &Process,
    monoclassdef_klass: i32,
    monoclass_vtable_size: i32,
    c: Address,
    n: u32,
) -> i32 {
    let Ok(vtable_size) = process.read::<u32>(c + monoclassdef_klass + monoclass_vtable_size) else {
        return 0;
    };
    if vtable_size == 0 { return 1; }
    if vtable_size == 434 { return 2; }
    if 0x100 <= vtable_size { return 3; }
    if vtable_size != n { return 4; }
    5
}

fn v2_v3_monovtable_vtable_score(
    process: &Process,
    deref_type: DerefType,
    map_name_class: &BTreeMap<String, Address>,
    monoclassdef_klass: i32,
    monoclassdef_field_count: i32,
    monoclass_fields: i32,
    monoclassfieldalignment: i32,
    monoclassfield_name: i32,
    monoclassfield_offset: i32,
    monoclass_runtime_info: i32,
    monoclassruntimeinfo_domain_vtables: i32,
    monoclass_vtable_size: i32,
    monovtable_vtable: i32,
) -> Option<i32> {
    let map_name_static_field_bytes: BTreeMap<&str, &[(&str, &[(&[(&str, &str)], &[u8])])]> = BTreeMap::from(NAME_STATIC_FIELD_BYTES);
    for (k, sfbs) in map_name_static_field_bytes {
        let Some(&c) = map_name_class.get(k) else {
            asr::print_message(&format!("map_name_class.get failed: {}", k));
            return None;
        };
        let Ok(runtime_info) = read_pointer(process, deref_type, c + monoclassdef_klass + monoclass_runtime_info) else {
            return Some(0);
        };
        // It's okay to be null?
        if runtime_info.is_null() {
            return Some(2);
        }
        let Ok(vtables) = read_pointer(process, deref_type, runtime_info + monoclassruntimeinfo_domain_vtables) else {
            return Some(0);
        };
        let Ok(vtable_size) = process.read::<u32>(c + monoclassdef_klass + monoclass_vtable_size) else {
            return Some(0);
        };
        let vtables2 = vtables + monovtable_vtable;
        let Ok(static_table) = read_pointer(process, deref_type, vtables2 + (vtable_size as u64).wrapping_mul(deref_type.size_of_ptr())) else {
            return Some(0);
        };
        for (sf, bs) in sfbs {
            let Some(offset) = class_field_name_offset(
                process,
                deref_type,
                c,
                sf,
                monoclassdef_klass,
                monoclassdef_field_count,
                monoclass_fields,
                monoclassfieldalignment,
                monoclassfield_name,
                monoclassfield_offset,
            ) else {
                return Some(1);
            };
            let mut a = static_table + offset;
            for (p, v) in bs.into_iter() {
                for &(vcn, vf) in p.into_iter() {
                    let Some(&vc) = map_name_class.get(vcn) else {
                        return Some(1);
                    };
                    let Some(o) = class_field_name_offset(process, deref_type, vc, vf, monoclassdef_klass, monoclassdef_field_count, monoclass_fields, monoclassfieldalignment, monoclassfield_name, monoclassfield_offset) else {
                        return Some(1);
                    };
                    let Ok(a2) = read_pointer(process, deref_type, a) else {
                        return Some(1);
                    };
                    a = a2 + o;
                }
                let Ok(v_actual) = process.read::<[u8; 1]>(a) else {
                    return Some(2);
                };
                // asr::print_message(&format!("v_acual: {:X?}, v: {:X?}", v_actual, v));
                if &v_actual != v { return Some(3); }
            }
        }
    }
    Some(4)
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

fn classes_no_next_iter<'a>(
    process: &'a Process,
    deref_type: DerefType,
    table_addr: Address,
    class_cache_size: i32,
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
                table = Address::NULL;
                Some(class)
            }
        })
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

fn classes_map(
    process: &Process,
    deref_type: DerefType,
    table_addr: Address,
    class_cache_size: i32,
    monoclassdef_klass: i32,
    monoclassdef_next_class_cache: i32,
    monoclass_name: i32,
) -> BTreeMap<String, Address> {
    let mut map_name_class: BTreeMap<String, Address> = BTreeMap::new();
    for c in classes_iter(process, deref_type, table_addr, class_cache_size, monoclassdef_next_class_cache) {
        let Some(k) = class_name(process, deref_type, c, monoclassdef_klass, monoclass_name) else {
            continue;
        };
        if !map_name_class.contains_key(&k) {
            map_name_class.insert(k, c);
        }
    }
    map_name_class
}

fn class_field_name_offset(
    process: &Process,
    deref_type: DerefType,
    c: Address,
    f: &str,
    monoclassdef_klass: i32,
    monoclassdef_field_count: i32,
    monoclass_fields: i32,
    monoclassfieldalignment: i32,
    monoclassfield_name: i32,
    monoclassfield_offset: i32,
) -> Option<u32> {
    for (k, v) in class_field_names_offsets_iter(
        process,
        deref_type,
        c,
        monoclassdef_klass,
        monoclassdef_field_count,
        monoclass_fields,
        monoclassfieldalignment,
        monoclassfield_name,
        monoclassfield_offset,
    ) {
        if k == f {
            return Some(v);
        }
    }
    None
}

fn class_field_names_offsets_iter<'a>(
    process: &'a Process,
    deref_type: DerefType,
    c: Address,
    monoclassdef_klass: i32,
    monoclassdef_field_count: i32,
    monoclass_fields: i32,
    monoclassfieldalignment: i32,
    monoclassfield_name: i32,
    monoclassfield_offset: i32,
) -> impl Iterator<Item = (String, u32)> + 'a {
    let field_count = process.read::<u32>(c + monoclassdef_field_count).unwrap_or_default();
    let fields = read_pointer(process, deref_type, c + monoclassdef_klass + monoclass_fields).unwrap_or_default();
    (0..field_count).map(move |i| -> (String, u32) {
        let field = fields + i.wrapping_mul(monoclassfieldalignment as u32);
        let name_addr = read_pointer(process, deref_type, field + monoclassfield_name).unwrap_or_default();
        let name_cstr = process.read::<ArrayCString<CSTR>>(name_addr).unwrap_or_default();
        let name_str = String::from_utf8(name_cstr.to_vec()).unwrap_or_default();
        let offset = process.read::<u32>(field + monoclassfield_offset).unwrap_or_default();
        (name_str, offset)
    })
}
