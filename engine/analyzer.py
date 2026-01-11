"""
RafSec Engine - Malware Analyzer (Enhanced)
============================================
Heuristic, signature, and YARA-based analysis engine.

Author: RafSec Team
Version: 2.0.0

Features:
- EICAR Test File detection
- YARA rules scanning
- Heuristic analysis
- Behavioral pattern detection
"""

import os
import sys
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

# Add project root to path
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# YARA support (optional)
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[WARNING] yara-python not installed. YARA scanning disabled.")


# EICAR Test String (industry standard)
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_STRING = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ThreatLevel(Enum):
    """Threat level classifications."""
    CLEAN = "CLEAN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class YaraMatch:
    """YARA rule match result."""
    rule_name: str
    description: str
    severity: str
    matched_strings: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Complete analysis result with scores and findings."""
    file_path: str
    threat_level: ThreatLevel
    suspicion_score: float  # 0.0 to 100.0
    
    # Component scores
    entropy_score: float = 0.0
    import_score: float = 0.0
    section_score: float = 0.0
    header_score: float = 0.0
    behavior_score: float = 0.0
    
    # YARA results
    yara_matches: List[YaraMatch] = field(default_factory=list)
    yara_score: float = 0.0
    
    # Special detections
    is_eicar: bool = False
    malware_name: Optional[str] = None
    
    # Findings
    findings: List[Dict[str, str]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Signature matches
    signature_matches: List[str] = field(default_factory=list)


class YaraScanner:
    """
    YARA rules scanner for signature-based detection.
    
    YARA is the industry standard for malware signature matching.
    It allows pattern matching with complex conditions.
    """
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize YARA scanner.
        
        Args:
            rules_dir: Directory containing .yar files
        """
        if not YARA_AVAILABLE:
            self.rules = None
            return
        
        self.rules_dir = rules_dir or os.path.join(BASE_DIR, 'rules')
        self.rules = None
        self._compile_rules()
    
    def _compile_rules(self) -> None:
        """Compile all YARA rules from the rules directory."""
        if not YARA_AVAILABLE:
            return
        
        if not os.path.exists(self.rules_dir):
            print(f"[WARNING] Rules directory not found: {self.rules_dir}")
            return
        
        # Find all .yar files
        rule_files = {}
        for filename in os.listdir(self.rules_dir):
            if filename.endswith(('.yar', '.yara')):
                filepath = os.path.join(self.rules_dir, filename)
                rule_name = os.path.splitext(filename)[0]
                rule_files[rule_name] = filepath
        
        if not rule_files:
            print("[INFO] No YARA rules found in rules directory.")
            return
        
        try:
            self.rules = yara.compile(filepaths=rule_files)
            print(f"[INFO] Loaded {len(rule_files)} YARA rule file(s)")
        except yara.SyntaxError as e:
            print(f"[ERROR] YARA syntax error: {e}")
            self.rules = None
        except Exception as e:
            print(f"[ERROR] Failed to compile YARA rules: {e}")
            self.rules = None
    
    def scan(self, file_path: str) -> List[YaraMatch]:
        """
        Scan a file with compiled YARA rules.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of YaraMatch objects for matches found
        """
        if not YARA_AVAILABLE or not self.rules:
            return []
        
        matches = []
        
        try:
            yara_matches = self.rules.match(file_path)
            
            for match in yara_matches:
                # Extract metadata from rule
                description = match.meta.get('description', 'No description')
                severity = match.meta.get('severity', 'unknown')
                
                # Extract matched strings
                matched_strings = []
                for string_match in match.strings:
                    # string_match format varies by yara-python version
                    try:
                        matched_strings.append(str(string_match))
                    except:
                        pass
                
                matches.append(YaraMatch(
                    rule_name=match.rule,
                    description=description,
                    severity=severity,
                    matched_strings=matched_strings[:5]  # Limit to 5
                ))
            
        except Exception as e:
            print(f"[WARNING] YARA scan error: {e}")
        
        return matches
    
    def scan_data(self, data: bytes) -> List[YaraMatch]:
        """Scan raw bytes with YARA rules."""
        if not YARA_AVAILABLE or not self.rules:
            return []
        
        matches = []
        
        try:
            yara_matches = self.rules.match(data=data)
            
            for match in yara_matches:
                description = match.meta.get('description', 'No description')
                severity = match.meta.get('severity', 'unknown')
                
                matches.append(YaraMatch(
                    rule_name=match.rule,
                    description=description,
                    severity=severity
                ))
                
        except Exception as e:
            print(f"[WARNING] YARA data scan error: {e}")
        
        return matches


class MalwareAnalyzer:
    """
    Heuristic malware analyzer with EICAR and YARA support.
    
    Detection pipeline:
    1. EICAR test file check (instant detection)
    2. YARA signature matching
    3. Heuristic analysis (entropy, imports, sections, etc.)
    4. Behavioral pattern detection
    """
    
    # Score weights for each component
    WEIGHTS = {
        'entropy': 25,
        'imports': 25,
        'sections': 20,
        'headers': 15,
        'behavior': 15,
    }
    
    # Known malware signatures (hash-based)
    KNOWN_MALWARE_HASHES = {
        '44d88612fea8a8f36de82e1278abb02f': 'EICAR-Test-File',
    }
    
    # Suspicious import patterns
    BEHAVIOR_PATTERNS = {
        'keylogger': ['GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState'],
        'injector': ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
        'downloader': ['URLDownloadToFileA', 'InternetOpenA', 'HttpOpenRequestA'],
        'credential_stealer': ['CredEnumerateA', 'CryptUnprotectData'],
        'ransomware': ['CryptEncrypt', 'CryptGenKey', 'CryptAcquireContextA'],
        'persistence': ['RegSetValueExA', 'CreateServiceA', 'RegisterServiceCtrlHandlerA'],
        'anti_analysis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
        'privilege_escalation': ['AdjustTokenPrivileges', 'OpenProcessToken', 'LookupPrivilegeValueA'],
    }
    
    def __init__(self, features=None):
        """
        Initialize analyzer.
        
        Args:
            features: PEFeatures object from PEExtractor (optional for EICAR-only scan)
        """
        self.features = features
        self.result: Optional[AnalysisResult] = None
        self.yara_scanner = YaraScanner()
    
    def check_eicar(self, file_path: str) -> Tuple[bool, str]:
        """
        Check if file is EICAR test file.
        
        The EICAR test file is a standard way to test antivirus detection
        without using actual malware. It's 68 bytes of ASCII text.
        
        Returns:
            Tuple of (is_eicar, message)
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1000)  # First 1KB is enough
            
            # Check for EICAR signature
            if EICAR_SIGNATURE in content or EICAR_STRING.encode() in content:
                return (True, "EICAR-Test-Signature detected")
            
            # Also check string version
            try:
                text_content = content.decode('ascii', errors='ignore')
                if EICAR_STRING in text_content:
                    return (True, "EICAR-Test-Signature detected")
            except:
                pass
            
            return (False, "")
            
        except Exception as e:
            return (False, f"Error checking EICAR: {e}")
    
    def analyze(self, file_path: Optional[str] = None) -> AnalysisResult:
        """
        Perform complete analysis.
        
        Returns:
            AnalysisResult with scores and findings
        """
        # Get file path from features if not provided
        if file_path is None and self.features:
            file_path = self.features.file_path
        
        if file_path is None:
            raise ValueError("No file path provided for analysis")
        
        self.result = AnalysisResult(
            file_path=file_path,
            threat_level=ThreatLevel.CLEAN,
            suspicion_score=0.0
        )
        
        # ============================================
        # STEP 1: EICAR Test File Check (Priority)
        # ============================================
        is_eicar, eicar_msg = self.check_eicar(file_path)
        if is_eicar:
            self.result.is_eicar = True
            self.result.malware_name = "EICAR-Test-Signature"
            self.result.threat_level = ThreatLevel.CRITICAL
            self.result.suspicion_score = 100.0
            self.result.findings.append({
                'type': 'EICAR',
                'severity': 'CRITICAL',
                'title': 'EICAR Test File Detected!',
                'detail': 'This is the standard antivirus test file.',
                'score': 100.0
            })
            self.result.recommendations.append(
                "🧪 EICAR test file detected - antivirus is working correctly!"
            )
            return self.result
        
        # ============================================
        # STEP 2: YARA Signature Scanning
        # ============================================
        yara_matches = self.yara_scanner.scan(file_path)
        if yara_matches:
            self.result.yara_matches = yara_matches
            
            for match in yara_matches:
                severity = match.severity.upper()
                
                # Calculate YARA score based on severity
                if severity == 'CRITICAL':
                    self.result.yara_score += 30
                elif severity == 'HIGH':
                    self.result.yara_score += 20
                elif severity == 'MEDIUM':
                    self.result.yara_score += 10
                else:
                    self.result.yara_score += 5
                
                self.result.findings.append({
                    'type': 'YARA',
                    'severity': severity if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] else 'MEDIUM',
                    'title': f'YARA Match: {match.rule_name}',
                    'detail': match.description,
                    'score': self.result.yara_score
                })
            
            # Cap YARA score
            self.result.yara_score = min(self.result.yara_score, 50)
        
        # ============================================
        # STEP 3: Heuristic Analysis (if features available)
        # ============================================
        if self.features:
            self._analyze_signatures()
            self._analyze_entropy()
            self._analyze_imports()
            self._analyze_sections()
            self._analyze_headers()
            self._analyze_behavior()
        
        # ============================================
        # STEP 4: Calculate Total Score
        # ============================================
        self.result.suspicion_score = (
            self.result.entropy_score +
            self.result.import_score +
            self.result.section_score +
            self.result.header_score +
            self.result.behavior_score +
            self.result.yara_score
        )
        
        # Cap at 100
        self.result.suspicion_score = min(self.result.suspicion_score, 100.0)
        
        # Determine threat level
        self.result.threat_level = self._calculate_threat_level()
        
        # Generate recommendations
        self._generate_recommendations()
        
        return self.result
    
    def _analyze_signatures(self) -> None:
        """Check against known malware signatures."""
        if self.features.md5 in self.KNOWN_MALWARE_HASHES:
            malware_name = self.KNOWN_MALWARE_HASHES[self.features.md5]
            self.result.signature_matches.append(malware_name)
            self.result.malware_name = malware_name
            self.result.suspicion_score = 100.0
            self.result.findings.append({
                'type': 'SIGNATURE',
                'severity': 'CRITICAL',
                'title': 'Known Malware Detected!',
                'detail': f"File matches known malware: {malware_name}",
                'score': 100.0
            })
    
    def _analyze_entropy(self) -> None:
        """Analyze file and section entropy."""
        overall = self.features.overall_entropy
        score = 0.0
        
        if overall < 6.5:
            score = 0.0
        elif overall < 7.0:
            score = 5.0
            self.result.findings.append({
                'type': 'ENTROPY',
                'severity': 'LOW',
                'title': 'Slightly elevated entropy',
                'detail': f"Overall entropy: {overall:.2f} (threshold: 6.5)",
                'score': score
            })
        elif overall < 7.5:
            score = 15.0
            self.result.findings.append({
                'type': 'ENTROPY',
                'severity': 'MEDIUM',
                'title': 'High entropy detected',
                'detail': f"Overall entropy: {overall:.2f} - Likely packed/compressed",
                'score': score
            })
        else:
            score = 25.0
            self.result.findings.append({
                'type': 'ENTROPY',
                'severity': 'HIGH',
                'title': 'Very high entropy!',
                'detail': f"Overall entropy: {overall:.2f} - Strong indicator of packing/encryption",
                'score': score
            })
        
        # Check individual sections
        for section in self.features.sections:
            if section.entropy > 7.0:
                score = min(score + 5, 25)
                self.result.findings.append({
                    'type': 'ENTROPY',
                    'severity': 'MEDIUM',
                    'title': f'High entropy section: {section.name}',
                    'detail': f"Section entropy: {section.entropy:.2f}",
                    'score': 5.0
                })
        
        self.result.entropy_score = score
    
    def _analyze_imports(self) -> None:
        """Analyze Import Address Table."""
        score = 0.0
        
        if not self.features.has_imports:
            score = 25.0
            self.result.findings.append({
                'type': 'IMPORTS',
                'severity': 'HIGH',
                'title': 'No import table detected!',
                'detail': 'Missing imports strongly indicates packed/obfuscated malware',
                'score': score
            })
            self.result.import_score = score
            return
        
        if self.features.total_imports < 5:
            score += 10.0
            self.result.findings.append({
                'type': 'IMPORTS',
                'severity': 'MEDIUM',
                'title': 'Very few imports',
                'detail': f"Only {self.features.total_imports} imports - could be packed",
                'score': 10.0
            })
        
        suspicious_count = len(self.features.suspicious_imports)
        
        if suspicious_count > 0:
            import_points = min(suspicious_count * 3, 15)
            score += import_points
            
            self.result.findings.append({
                'type': 'IMPORTS',
                'severity': 'MEDIUM' if suspicious_count < 4 else 'HIGH',
                'title': f'{suspicious_count} suspicious API calls detected',
                'detail': ', '.join(self.features.suspicious_imports[:5]) + 
                         ('...' if suspicious_count > 5 else ''),
                'score': import_points
            })
        
        self.result.import_score = min(score, 25)
    
    def _analyze_sections(self) -> None:
        """Analyze PE sections."""
        score = 0.0
        
        for section in self.features.sections:
            if section.is_writable and section.is_executable:
                score += 10.0
                self.result.findings.append({
                    'type': 'SECTION',
                    'severity': 'HIGH',
                    'title': f'WRITE+EXECUTE section: {section.name}',
                    'detail': 'Self-modifying code capability - common in malware/packers',
                    'score': 10.0
                })
            
            if section.raw_size == 0 and section.virtual_size > 0:
                score += 5.0
                self.result.findings.append({
                    'type': 'SECTION',
                    'severity': 'MEDIUM',
                    'title': f'Zero-size section: {section.name}',
                    'detail': 'Section has no raw data but virtual size - runtime unpacking?',
                    'score': 5.0
                })
        
        if self.features.entry_point_anomaly:
            score += 5.0
            self.result.findings.append({
                'type': 'SECTION',
                'severity': 'MEDIUM',
                'title': 'Entry point in non-standard section',
                'detail': f"EP is in '{self.features.entry_point_section}' instead of .text",
                'score': 5.0
            })
        
        self.result.section_score = min(score, 20)
    
    def _analyze_headers(self) -> None:
        """Analyze PE headers."""
        score = 0.0
        
        if self.features.e_lfanew_anomaly:
            score += 5.0
            self.result.findings.append({
                'type': 'HEADER',
                'severity': 'MEDIUM',
                'title': 'Large e_lfanew offset',
                'detail': f"DOS->PE offset: {hex(self.features.e_lfanew)} - possible hidden code",
                'score': 5.0
            })
        
        for anomaly in self.features.anomalies:
            if 'timestamp' in anomaly.lower():
                score += 5.0
                self.result.findings.append({
                    'type': 'HEADER',
                    'severity': 'LOW',
                    'title': 'Timestamp anomaly',
                    'detail': anomaly,
                    'score': 5.0
                })
        
        self.result.header_score = min(score, 15)
    
    def _analyze_behavior(self) -> None:
        """Detect behavioral patterns."""
        score = 0.0
        import_set = set()
        
        for dll_imports in self.features.suspicious_imports:
            if ':' in dll_imports:
                _, func = dll_imports.split(':', 1)
                import_set.add(func)
        
        for behavior, required_funcs in self.BEHAVIOR_PATTERNS.items():
            matches = [f for f in required_funcs if f in import_set]
            
            if len(matches) >= 2:
                score += 5.0
                self.result.findings.append({
                    'type': 'BEHAVIOR',
                    'severity': 'HIGH',
                    'title': f'{behavior.upper()} behavior detected',
                    'detail': f"Matching APIs: {', '.join(matches)}",
                    'score': 5.0
                })
        
        has_evasion = any(f in import_set for f in self.BEHAVIOR_PATTERNS['anti_analysis'])
        has_payload = (
            any(f in import_set for f in self.BEHAVIOR_PATTERNS['injector']) or
            any(f in import_set for f in self.BEHAVIOR_PATTERNS['ransomware'])
        )
        
        if has_evasion and has_payload:
            score += 5.0
            self.result.findings.append({
                'type': 'BEHAVIOR',
                'severity': 'CRITICAL',
                'title': 'Evasion + Payload delivery combination!',
                'detail': 'File uses anti-analysis AND dangerous capabilities',
                'score': 5.0
            })
        
        self.result.behavior_score = min(score, 15)
    
    def _calculate_threat_level(self) -> ThreatLevel:
        """Determine threat level based on total score."""
        score = self.result.suspicion_score
        
        # Boost threat level if YARA matches critical rules
        has_critical_yara = any(
            m.severity.upper() == 'CRITICAL' 
            for m in self.result.yara_matches
        )
        
        if score >= 75 or has_critical_yara:
            return ThreatLevel.CRITICAL
        elif score >= 50:
            return ThreatLevel.HIGH
        elif score >= 30:
            return ThreatLevel.MEDIUM
        elif score >= 10:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.CLEAN
    
    def _generate_recommendations(self) -> None:
        """Generate actionable recommendations."""
        level = self.result.threat_level
        
        if self.result.is_eicar:
            return  # Already handled
        
        if level == ThreatLevel.CLEAN:
            self.result.recommendations.append(
                "✅ No significant threats detected. File appears clean."
            )
            self.result.recommendations.append(
                "Consider dynamic analysis for complete verification."
            )
        
        elif level == ThreatLevel.LOW:
            self.result.recommendations.append(
                "⚠️ Minor suspicious indicators found. Proceed with caution."
            )
            self.result.recommendations.append(
                "Scan with additional antivirus engines for confirmation."
            )
        
        elif level == ThreatLevel.MEDIUM:
            self.result.recommendations.append(
                "⚠️ Multiple suspicious indicators detected."
            )
            self.result.recommendations.append(
                "DO NOT execute this file without sandbox analysis."
            )
        
        elif level == ThreatLevel.HIGH:
            self.result.recommendations.append(
                "🚨 HIGH RISK: File shows strong malware indicators!"
            )
            self.result.recommendations.append(
                "Quarantine immediately. Do not execute."
            )
        
        elif level == ThreatLevel.CRITICAL:
            self.result.recommendations.append(
                "🚨 CRITICAL: File is almost certainly malicious!"
            )
            self.result.recommendations.append(
                "QUARANTINE OR DELETE IMMEDIATELY!"
            )
            if self.result.yara_matches:
                self.result.recommendations.append(
                    f"YARA detected: {', '.join(m.rule_name for m in self.result.yara_matches)}"
                )
    
    def get_report(self) -> str:
        """Generate human-readable report."""
        if not self.result:
            self.analyze()
        
        report = []
        report.append("=" * 60)
        report.append("          RAFSEC MALWARE ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"File: {self.result.file_path}")
        report.append(f"Threat Level: {self.result.threat_level.value}")
        report.append(f"Suspicion Score: {self.result.suspicion_score:.1f}/100")
        
        if self.result.malware_name:
            report.append(f"Malware Name: {self.result.malware_name}")
        
        if self.result.yara_matches:
            report.append("")
            report.append("-" * 40)
            report.append("YARA MATCHES:")
            for match in self.result.yara_matches:
                report.append(f"  [{match.severity.upper()}] {match.rule_name}")
                report.append(f"          └─ {match.description}")
        
        report.append("")
        report.append("-" * 40)
        report.append("SCORE BREAKDOWN:")
        report.append(f"  Entropy Analysis:  {self.result.entropy_score:.1f}/25")
        report.append(f"  Import Analysis:   {self.result.import_score:.1f}/25")
        report.append(f"  Section Analysis:  {self.result.section_score:.1f}/20")
        report.append(f"  Header Analysis:   {self.result.header_score:.1f}/15")
        report.append(f"  Behavior Analysis: {self.result.behavior_score:.1f}/15")
        if self.result.yara_score > 0:
            report.append(f"  YARA Score:        {self.result.yara_score:.1f}")
        
        if self.result.findings:
            report.append("")
            report.append("-" * 40)
            report.append("FINDINGS:")
            for finding in self.result.findings:
                severity = finding['severity']
                title = finding['title']
                detail = finding['detail']
                report.append(f"  [{severity}] {title}")
                report.append(f"          └─ {detail}")
        
        report.append("")
        report.append("-" * 40)
        report.append("RECOMMENDATIONS:")
        for rec in self.result.recommendations:
            report.append(f"  • {rec}")
        
        report.append("=" * 60)
        
        return "\n".join(report)
