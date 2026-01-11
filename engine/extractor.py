"""
RafSec Engine - PE Feature Extractor
=====================================
Extracts static features from Windows PE files for malware analysis.

Author: RafSec Team

WHY STATIC ANALYSIS:
- Malware doesn't need to run to be analyzed
- Safer than dynamic analysis (no risk of infection)
- Fast - can scan thousands of files quickly
- Reveals structural anomalies that packers/malware create
"""

import pefile
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from utils.helpers import EntropyCalculator, FileHasher


@dataclass
class SectionInfo:
    """Data class for PE section information."""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: int
    is_executable: bool
    is_writable: bool
    is_readable: bool


@dataclass
class ImportInfo:
    """Data class for import table information."""
    dll_name: str
    functions: List[str] = field(default_factory=list)


@dataclass
class PEFeatures:
    """Complete extracted features from a PE file."""
    # File metadata
    file_path: str
    file_size: int
    
    # Hashes
    md5: str = ""
    sha256: str = ""
    sha1: str = ""
    imphash: str = ""
    
    # Headers
    machine_type: str = ""
    timestamp: int = 0
    timestamp_readable: str = ""
    subsystem: str = ""
    dll_characteristics: int = 0
    
    # DOS Header anomalies
    dos_header_valid: bool = True
    e_lfanew: int = 0  # Offset to PE header
    e_lfanew_anomaly: bool = False
    
    # Sections
    number_of_sections: int = 0
    sections: List[SectionInfo] = field(default_factory=list)
    overall_entropy: float = 0.0
    
    # Entry Point
    entry_point: int = 0
    entry_point_section: str = ""
    entry_point_anomaly: bool = False
    
    # Imports
    has_imports: bool = False
    imports: List[ImportInfo] = field(default_factory=list)
    total_imports: int = 0
    suspicious_imports: List[str] = field(default_factory=list)
    
    # Resources
    has_resources: bool = False
    resource_entropy: float = 0.0
    
    # Anomalies detected
    anomalies: List[str] = field(default_factory=list)


class PEExtractor:
    """
    Extracts security-relevant features from PE (Portable Executable) files.
    
    This class dissects the PE structure to find indicators of malicious
    behavior without executing the file.
    """
    
    # Suspicious function imports that malware commonly uses
    SUSPICIOUS_IMPORTS = [
        # Process manipulation (used for injection)
        'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
        'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
        'NtUnmapViewOfSection', 'NtWriteVirtualMemory',
        
        # Code injection
        'LoadLibraryA', 'LoadLibraryW', 'GetProcAddress',
        'SetWindowsHookEx', 'SetWindowsHookExA', 'SetWindowsHookExW',
        
        # Keyloggers/Spyware
        'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState',
        'SetWindowsHookExA', 'RegisterHotKey',
        
        # Anti-debugging/Anti-VM (evasion)
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'OutputDebugString',
        
        # Network (C2 communication)
        'InternetOpenA', 'InternetOpenW', 'InternetConnectA',
        'HttpOpenRequestA', 'URLDownloadToFileA', 'WinHttpOpen',
        
        # Registry (persistence)
        'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyExA',
        
        # Cryptography (ransomware indicator)
        'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContextA',
        'CryptGenKey', 'CryptDeriveKey',
        
        # File operations (ransomware/wiper)
        'DeleteFileA', 'DeleteFileW', 'MoveFileA', 'CopyFileA',
        
        # Privilege escalation
        'AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA',
        
        # Screenshot/Clipboard (spyware)
        'GetDC', 'BitBlt', 'CreateCompatibleBitmap', 'GetClipboardData',
    ]
    
    # Suspicious section names (packers/malware indicators)
    SUSPICIOUS_SECTIONS = [
        '.upx', '.upx0', '.upx1', '.upx2',  # UPX packer
        '.aspack', '.adata',                  # ASPack
        '.nsp0', '.nsp1', '.nsp2',           # NsPack
        '.packed', '.pec2',                   # PECompact
        '.themida', '.winlice',              # Themida
        '.vmp0', '.vmp1', '.vmp2',           # VMProtect
        '.petite', '.yoda',                   # Other packers
        '.fucks', '.shit', '.evil',          # Obvious malware
        '.text0', '.text1',                   # Modified sections
    ]
    
    # Machine type mapping
    MACHINE_TYPES = {
        0x14c: 'i386 (32-bit)',
        0x8664: 'AMD64 (64-bit)',
        0x1c0: 'ARM',
        0xaa64: 'ARM64',
    }
    
    # Subsystem mapping
    SUBSYSTEMS = {
        1: 'Native',
        2: 'Windows GUI',
        3: 'Windows Console',
        7: 'POSIX',
        9: 'Windows CE',
        10: 'EFI Application',
    }
    
    def __init__(self, file_path: str):
        """
        Initialize extractor with target PE file.
        
        Args:
            file_path: Path to the PE file to analyze
        """
        self.file_path = file_path
        self.pe: Optional[pefile.PE] = None
        self.features: Optional[PEFeatures] = None
    
    def load(self) -> bool:
        """
        Load and parse the PE file.
        
        Returns:
            True if successfully loaded, False otherwise
        """
        try:
            # fast_load=False ensures all directories are parsed
            self.pe = pefile.PE(self.file_path, fast_load=False)
            return True
        except pefile.PEFormatError as e:
            print(f"[ERROR] Invalid PE format: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to load file: {e}")
            return False
    
    def extract_all(self) -> PEFeatures:
        """
        Extract ALL security-relevant features from the PE file.
        
        Returns:
            PEFeatures dataclass with all extracted information
        """
        if not self.pe:
            if not self.load():
                raise ValueError("Failed to load PE file")
        
        import os
        self.features = PEFeatures(
            file_path=self.file_path,
            file_size=os.path.getsize(self.file_path)
        )
        
        # Extract each component
        self._extract_hashes()
        self._extract_dos_header()
        self._extract_file_header()
        self._extract_optional_header()
        self._extract_sections()
        self._extract_imports()
        self._extract_entry_point()
        self._check_resources()
        
        # Calculate overall file entropy
        with open(self.file_path, 'rb') as f:
            self.features.overall_entropy = EntropyCalculator.calculate(f.read())
        
        return self.features
    
    def _extract_hashes(self) -> None:
        """Extract all file hashes."""
        hashes = FileHasher.get_all_hashes(self.file_path, self.pe)
        self.features.md5 = hashes['md5']
        self.features.sha1 = hashes['sha1']
        self.features.sha256 = hashes['sha256']
        self.features.imphash = hashes.get('imphash', 'N/A')
    
    def _extract_dos_header(self) -> None:
        """
        Extract DOS header information.
        
        WHY CHECK DOS HEADER:
        - e_lfanew points to the PE header. If this offset is abnormally
          large, it might be hiding malicious code between DOS and PE headers.
        - Some malware modifies DOS header for anti-analysis.
        """
        dos = self.pe.DOS_HEADER
        self.features.e_lfanew = dos.e_lfanew
        
        # Normal e_lfanew is around 0x80-0x100. Larger values are suspicious.
        if dos.e_lfanew > 0x200:
            self.features.e_lfanew_anomaly = True
            self.features.anomalies.append(
                f"Suspicious e_lfanew offset: {hex(dos.e_lfanew)} (possible hidden code)"
            )
    
    def _extract_file_header(self) -> None:
        """
        Extract FILE_HEADER information.
        
        Contains machine type, number of sections, timestamp.
        """
        fh = self.pe.FILE_HEADER
        
        # Machine type (32-bit vs 64-bit)
        self.features.machine_type = self.MACHINE_TYPES.get(
            fh.Machine, f'Unknown ({hex(fh.Machine)})'
        )
        
        # Compilation timestamp
        self.features.timestamp = fh.TimeDateStamp
        import datetime
        try:
            self.features.timestamp_readable = datetime.datetime.utcfromtimestamp(
                fh.TimeDateStamp
            ).strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            self.features.timestamp_readable = "Invalid timestamp"
        
        # Check for suspicious timestamp (in the future or very old)
        if fh.TimeDateStamp > 2000000000:  # Year ~2033
            self.features.anomalies.append("Timestamp is in the future (anti-analysis?)")
        elif fh.TimeDateStamp < 946684800:  # Before year 2000
            self.features.anomalies.append("Timestamp before Y2K (likely tampered)")
        
        self.features.number_of_sections = fh.NumberOfSections
    
    def _extract_optional_header(self) -> None:
        """Extract OPTIONAL_HEADER information."""
        oh = self.pe.OPTIONAL_HEADER
        
        # Subsystem determines if it's Console, GUI, Driver, etc.
        self.features.subsystem = self.SUBSYSTEMS.get(
            oh.Subsystem, f'Unknown ({oh.Subsystem})'
        )
        
        self.features.dll_characteristics = oh.DllCharacteristics
        self.features.entry_point = oh.AddressOfEntryPoint
    
    def _extract_sections(self) -> None:
        """
        Extract and analyze all PE sections.
        
        WHY SECTION ANALYSIS IS CRITICAL:
        - Each section should have reasonable entropy (6-7)
        - Packed malware has sections with entropy > 7.0
        - Suspicious section names (.upx, .vmp) indicate packers
        - Writeable + Executable sections are dangerous (self-modifying code)
        """
        for section in self.pe.sections:
            try:
                name = section.Name.decode('utf-8').rstrip('\x00')
            except:
                name = section.Name.rstrip(b'\x00').decode('latin-1')
            
            # Calculate section entropy
            section_data = section.get_data()
            entropy = EntropyCalculator.calculate(section_data)
            
            # Check characteristics flags
            chars = section.Characteristics
            is_exec = bool(chars & 0x20000000)    # IMAGE_SCN_MEM_EXECUTE
            is_write = bool(chars & 0x80000000)   # IMAGE_SCN_MEM_WRITE
            is_read = bool(chars & 0x40000000)    # IMAGE_SCN_MEM_READ
            
            section_info = SectionInfo(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                entropy=entropy,
                characteristics=chars,
                is_executable=is_exec,
                is_writable=is_write,
                is_readable=is_read
            )
            
            self.features.sections.append(section_info)
            
            # Check for anomalies
            if name.lower() in [s.lower() for s in self.SUSPICIOUS_SECTIONS]:
                self.features.anomalies.append(
                    f"Suspicious section name: {name} (known packer/malware)"
                )
            
            if entropy > 7.0:
                self.features.anomalies.append(
                    f"High entropy in section {name}: {entropy:.2f} (packed/encrypted?)"
                )
            
            if is_exec and is_write:
                self.features.anomalies.append(
                    f"Section {name} is WRITE+EXECUTE (self-modifying code!)"
                )
    
    def _extract_imports(self) -> None:
        """
        Extract Import Address Table (IAT).
        
        WHY IAT ANALYSIS IS CRUCIAL:
        - The IAT tells us what Windows functions the program calls
        - Malware needs specific APIs: VirtualAlloc (shellcode), 
          CreateRemoteThread (injection), GetAsyncKeyState (keylogger)
        - No imports at all? Likely packed - real imports are hidden
        """
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            self.features.has_imports = False
            self.features.anomalies.append(
                "No import table! (Highly suspicious - likely packed/obfuscated)"
            )
            return
        
        self.features.has_imports = True
        
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll_name = entry.dll.decode('utf-8')
            except:
                dll_name = entry.dll.decode('latin-1')
            
            import_info = ImportInfo(dll_name=dll_name)
            
            for func in entry.imports:
                if func.name:
                    try:
                        func_name = func.name.decode('utf-8')
                    except:
                        func_name = func.name.decode('latin-1')
                    
                    import_info.functions.append(func_name)
                    self.features.total_imports += 1
                    
                    # Check if this is a suspicious import
                    if func_name in self.SUSPICIOUS_IMPORTS:
                        self.features.suspicious_imports.append(
                            f"{dll_name}:{func_name}"
                        )
            
            self.features.imports.append(import_info)
    
    def _extract_entry_point(self) -> None:
        """
        Analyze the entry point location.
        
        WHY ENTRY POINT MATTERS:
        - Normal programs start execution in .text section
        - If entry point is in a different section (e.g., .data, .upx),
          it's suspicious - likely packed or modified
        """
        ep = self.features.entry_point
        ep_section = None
        
        for section in self.pe.sections:
            section_start = section.VirtualAddress
            section_end = section_start + section.Misc_VirtualSize
            
            if section_start <= ep < section_end:
                try:
                    ep_section = section.Name.decode('utf-8').rstrip('\x00')
                except:
                    ep_section = section.Name.rstrip(b'\x00').decode('latin-1')
                break
        
        self.features.entry_point_section = ep_section or "UNKNOWN"
        
        # Check for anomalies
        if ep_section is None:
            self.features.entry_point_anomaly = True
            self.features.anomalies.append(
                "Entry point outside any section! (Very suspicious)"
            )
        elif ep_section.lower() not in ['.text', 'code', '.code']:
            self.features.entry_point_anomaly = True
            self.features.anomalies.append(
                f"Entry point in non-standard section: {ep_section}"
            )
    
    def _check_resources(self) -> None:
        """
        Check PE resources for embedded content.
        
        WHY CHECK RESOURCES:
        - Malware often embeds payloads (DLLs, EXEs, scripts) in resources
        - High entropy resources = encrypted/compressed payload
        """
        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            self.features.has_resources = True
            # Could expand this to analyze individual resources
    
    def get_summary(self) -> Dict[str, Any]:
        """Return a summary dictionary of extracted features."""
        if not self.features:
            self.extract_all()
        
        return {
            'file': self.features.file_path,
            'size': self.features.file_size,
            'hashes': {
                'md5': self.features.md5,
                'sha256': self.features.sha256,
                'imphash': self.features.imphash
            },
            'machine': self.features.machine_type,
            'subsystem': self.features.subsystem,
            'sections': self.features.number_of_sections,
            'entropy': self.features.overall_entropy,
            'imports': self.features.total_imports,
            'suspicious_imports': len(self.features.suspicious_imports),
            'anomalies': len(self.features.anomalies)
        }
    
    def close(self) -> None:
        """Release PE file resources."""
        if self.pe:
            self.pe.close()
