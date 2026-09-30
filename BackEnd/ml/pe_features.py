import math
import os
import struct
from collections import Counter

SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "createremotethread", "createremotethreadex",
    "winexec", "shellexecutea", "shellexecutew", "createprocessa", "createprocessw",
    "openprocess", "ntunmapviewofsection", "queueuserapc", "setthreadcontext",
    "loadlibrarya", "loadlibraryw", "getprocaddress",
    "urldownloadtofilea", "urldownloadtofilew", "internetopenurl",
    "internetreadfile", "regsetvalueex", "regcreatekeyex",
    "deletefilea", "deletefilew", "copyfilea", "copyfilew", "movefilea", "movefilew",
    "powershell", "schtasks", "wscript", "cscript", "cmd.exe",
}
NORMAL_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata",
    ".pdata", ".bss", ".tls", ".crt", ".code", ".code32", ".code64"
}
SUSPICIOUS_SECTION_KEYWORDS = (
    "upx", "aspack", "themida", "packed", "crypted", "vmp", "enigma", "petite"
)

PE_FEATURES = [
    "e_magic","e_cblp","e_cp","e_crlc","e_cparhdr","e_minalloc","e_maxalloc","e_ss","e_sp",
    "e_csum","e_ip","e_cs","e_lfarlc","e_ovno","e_oemid","e_oeminfo","e_lfanew","Machine",
    "NumberOfSections","TimeDateStamp","PointerToSymbolTable","NumberOfSymbols",
    "SizeOfOptionalHeader","Characteristics","Magic","MajorLinkerVersion","MinorLinkerVersion",
    "SizeOfCode","SizeOfInitializedData","SizeOfUninitializedData","AddressOfEntryPoint","BaseOfCode",
    "ImageBase","SectionAlignment","FileAlignment","MajorOperatingSystemVersion",
    "MinorOperatingSystemVersion","MajorImageVersion","MinorImageVersion","MajorSubsystemVersion",
    "MinorSubsystemVersion","SizeOfHeaders","CheckSum","SizeOfImage","Subsystem","DllCharacteristics",
    "SizeOfStackReserve","SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit","LoaderFlags",
    "NumberOfRvaAndSizes","SuspiciousImportFunctions","SuspiciousNameSection","SectionsLength",
    "SectionMinEntropy","SectionMaxEntropy","SectionMinRawsize","SectionMaxRawsize",
    "SectionMinVirtualsize","SectionMaxVirtualsize","SectionMaxPointerData","SectionMinPointerData",
    "SectionMaxChar","SectionMainChar","DirectoryEntryImport","DirectoryEntryImportSize",
    "DirectoryEntryExport","ImageDirectoryEntryExport","ImageDirectoryEntryImport",
    "ImageDirectoryEntryResource","ImageDirectoryEntryException","ImageDirectoryEntrySecurity"
]

def _u16(buf, off): return struct.unpack_from("<H", buf, off)[0]
def _u32(buf, off): return struct.unpack_from("<I", buf, off)[0]
def _u64(buf, off): return struct.unpack_from("<Q", buf, off)[0]

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = float(len(data))
    return float(-sum((count/n) * math.log2(count/n) for count in counts.values()))

def parse_pe_features(file_path: str) -> tuple[dict, dict]:
    """Safely parse PE headers/sections/import table without executing the file."""
    with open(file_path, "rb") as handle:
        data = handle.read()

    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("Not a Windows PE executable: missing MZ header.")

    e_lfanew = _u32(data, 0x3C)
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew+4] != b"PE\0\0":
        raise ValueError("Invalid PE file: missing PE signature.")

    file_off = e_lfanew + 4
    machine = _u16(data, file_off)
    nsec = _u16(data, file_off+2)
    timestamp = _u32(data, file_off+4)
    ptr_sym = _u32(data, file_off+8)
    nsyms = _u32(data, file_off+12)
    sz_opt = _u16(data, file_off+16)
    characteristics = _u16(data, file_off+18)

    opt_off = file_off + 20
    if opt_off + sz_opt > len(data):
        raise ValueError("PE optional header extends past the file.")

    magic = _u16(data, opt_off)
    if magic not in (0x10B, 0x20B):
        raise ValueError("Unsupported PE optional-header format.")

    pe32plus = magic == 0x20B

    def u32s(offset):
        return _u32(data, opt_off + offset)
    def u16s(offset):
        return _u16(data, opt_off + offset)
    def pointer(offset):
        return _u64(data, opt_off + offset) if pe32plus else _u32(data, opt_off + offset)

    values = {
        "e_magic": _u16(data, 0),
        "e_cblp": _u16(data, 0x2),
        "e_cp": _u16(data, 0x4),
        "e_crlc": _u16(data, 0x6),
        "e_cparhdr": _u16(data, 0x8),
        "e_minalloc": _u16(data, 0xA),
        "e_maxalloc": _u16(data, 0xC),
        "e_ss": _u16(data, 0xE),
        "e_sp": _u16(data, 0x10),
        "e_csum": _u16(data, 0x12),
        "e_ip": _u16(data, 0x14),
        "e_cs": _u16(data, 0x16),
        "e_lfarlc": _u16(data, 0x18),
        "e_ovno": _u16(data, 0x1A),
        "e_oemid": _u16(data, 0x24),
        "e_oeminfo": _u16(data, 0x26),
        "e_lfanew": e_lfanew,
        "Machine": machine,
        "NumberOfSections": nsec,
        "TimeDateStamp": timestamp,
        "PointerToSymbolTable": ptr_sym,
        "NumberOfSymbols": nsyms,
        "SizeOfOptionalHeader": sz_opt,
        "Characteristics": characteristics,
        "Magic": magic,
        "MajorLinkerVersion": data[opt_off+2],
        "MinorLinkerVersion": data[opt_off+3],
        "SizeOfCode": u32s(4),
        "SizeOfInitializedData": u32s(8),
        "SizeOfUninitializedData": u32s(12),
        "AddressOfEntryPoint": u32s(16),
        "BaseOfCode": u32s(20),
        "ImageBase": pointer(24 if pe32plus else 28),
        "SectionAlignment": u32s(32),
        "FileAlignment": u32s(36),
        "MajorOperatingSystemVersion": u16s(40),
        "MinorOperatingSystemVersion": u16s(42),
        "MajorImageVersion": u16s(44),
        "MinorImageVersion": u16s(46),
        "MajorSubsystemVersion": u16s(48),
        "MinorSubsystemVersion": u16s(50),
        "SizeOfHeaders": u32s(60),
        "CheckSum": u32s(64),
        "SizeOfImage": u32s(56),
        "Subsystem": u16s(68),
        "DllCharacteristics": u16s(70),
        "SizeOfStackReserve": pointer(72),
        "SizeOfStackCommit": pointer(80 if pe32plus else 76),
        "SizeOfHeapReserve": pointer(88 if pe32plus else 80),
        "SizeOfHeapCommit": pointer(96 if pe32plus else 84),
        "LoaderFlags": u32s(108 if pe32plus else 88),
        "NumberOfRvaAndSizes": u32s(112 if pe32plus else 92),
    }

    dd_off = opt_off + (112 if pe32plus else 96)
    directories = []
    for i in range(min(int(values["NumberOfRvaAndSizes"]), 16)):
        if dd_off + i*8 + 8 <= len(data):
            directories.append((_u32(data, dd_off+i*8), _u32(data, dd_off+i*8+4)))
        else:
            directories.append((0, 0))
    while len(directories) < 16:
        directories.append((0, 0))

    sec_off = opt_off + sz_opt
    sections = []
    for i in range(min(nsec, 96)):
        off = sec_off + i*40
        if off + 40 > len(data):
            break
        name = data[off:off+8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = _u32(data, off+8)
        virtual_address = _u32(data, off+12)
        raw_size = _u32(data, off+16)
        raw_pointer = _u32(data, off+20)
        section_chars = _u32(data, off+36)
        if raw_pointer < len(data):
            raw = data[raw_pointer:min(len(data), raw_pointer + raw_size)]
        else:
            raw = b""
        sections.append({
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_pointer": raw_pointer,
            "characteristics": section_chars,
            "entropy": _entropy(raw[:4*1024*1024]),
        })

    def rva_to_offset(rva: int) -> int:
        if not rva:
            return 0
        for section in sections:
            start = section["virtual_address"]
            end = start + max(section["virtual_size"], section["raw_size"])
            if start <= rva < end:
                candidate = section["raw_pointer"] + (rva - start)
                return candidate if 0 <= candidate < len(data) else 0
        return int(rva) if 0 <= rva < len(data) else 0

    import_rva, import_size = directories[1]
    import_count = 0
    suspicious_import_count = 0
    imported_names = []

    import_off = rva_to_offset(import_rva)
    ptr_size = 8 if pe32plus else 4
    if import_off:
        desc_off = import_off
        for _ in range(4096):
            if desc_off + 20 > len(data):
                break
            oft = _u32(data, desc_off)
            name_rva = _u32(data, desc_off+12)
            first_thunk = _u32(data, desc_off+16)
            if oft == 0 and name_rva == 0 and first_thunk == 0:
                break
            import_count += 1
            thunk_rva = oft or first_thunk
            thunk_off = rva_to_offset(thunk_rva)
            if thunk_off:
                for j in range(20000):
                    item_off = thunk_off + j*ptr_size
                    if item_off + ptr_size > len(data):
                        break
                    thunk_value = _u64(data, item_off) if pe32plus else _u32(data, item_off)
                    if thunk_value == 0:
                        break
                    ordinal_flag = 1 << (63 if pe32plus else 31)
                    if thunk_value & ordinal_flag:
                        continue
                    name_off = rva_to_offset(thunk_value & 0x7FFFFFFF)
                    if name_off and name_off + 2 < len(data):
                        end = data.find(b"\0", name_off+2)
                        if end < 0:
                            end = min(len(data), name_off + 258)
                        function_name = data[name_off+2:end].decode("ascii", "replace")
                        imported_names.append(function_name)
                        lowered = function_name.lower()
                        if lowered in SUSPICIOUS_IMPORTS or any(
                            key in lowered for key in
                            ("virtualalloc", "writeprocessmemory", "createremotethread", "powershell")
                        ):
                            suspicious_import_count += 1
            desc_off += 20

    export_rva, export_size = directories[0]
    export_count = 0
    export_off = rva_to_offset(export_rva)
    if export_off and export_off + 40 <= len(data):
        export_count = _u32(data, export_off+24)

    def minmax(key):
        if not sections:
            return (0.0, 0.0)
        values_local = [float(section[key]) for section in sections]
        return min(values_local), max(values_local)

    e_min, e_max = minmax("entropy")
    raw_min, raw_max = minmax("raw_size")
    virt_min, virt_max = minmax("virtual_size")
    ptr_min, ptr_max = minmax("raw_pointer")
    char_min, char_max = minmax("characteristics")

    suspicious_section_names = [
        section["name"] for section in sections
        if section["name"].lower() not in NORMAL_SECTION_NAMES
        or any(k in section["name"].lower() for k in SUSPICIOUS_SECTION_KEYWORDS)
    ]

    values.update({
        "SuspiciousImportFunctions": suspicious_import_count,
        "SuspiciousNameSection": len(suspicious_section_names),
        "SectionsLength": len(sections),
        "SectionMinEntropy": e_min,
        "SectionMaxEntropy": e_max,
        "SectionMinRawsize": raw_min,
        "SectionMaxRawsize": raw_max,
        "SectionMinVirtualsize": virt_min,
        "SectionMaxVirtualsize": virt_max,
        "SectionMaxPointerData": ptr_max,
        "SectionMinPointerData": ptr_min,
        "SectionMaxChar": char_max,
        "SectionMainChar": sections[0]["characteristics"] if sections else 0,
        "DirectoryEntryImport": import_count,
        "DirectoryEntryImportSize": import_size,
        "DirectoryEntryExport": export_count,
        "ImageDirectoryEntryExport": export_rva,
        "ImageDirectoryEntryImport": import_rva,
        "ImageDirectoryEntryResource": directories[2][0],
        "ImageDirectoryEntryException": directories[3][0],
        "ImageDirectoryEntrySecurity": directories[4][0],
    })

    features = {name: float(values.get(name, 0)) for name in PE_FEATURES}
    info = {
        "size": os.path.getsize(file_path),
        "pe32plus": pe32plus,
        "sections": sections,
        "imports_sample": imported_names[:100],
        "suspicious_imports": suspicious_import_count,
        "suspicious_section_names": suspicious_section_names,
        "directories": {
            "export": export_rva,
            "import": import_rva,
            "resource": directories[2][0],
            "exception": directories[3][0],
            "security": directories[4][0],
        }
    }
    return features, info
