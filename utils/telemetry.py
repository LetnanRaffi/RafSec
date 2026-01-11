"""
RafSec Utils - Telemetry & MITRE ATT&CK Logger
===============================================
Structured threat logging for forensic analysis.

Author: RafSec Team
"""

import os
import json
import socket
import hashlib
from datetime import datetime
from typing import Dict, Optional, List


class EventLogger:
    """
    MITRE ATT&CK compliant event logger.
    
    Creates structured JSON logs for all security events,
    enabling forensic analysis and SIEM integration.
    """
    
    # MITRE ATT&CK technique descriptions
    MITRE_TECHNIQUES = {
        'T1059': 'Command and Scripting Interpreter',
        'T1059.001': 'PowerShell',
        'T1059.003': 'Windows Command Shell',
        'T1059.005': 'Visual Basic',
        'T1204.002': 'Malicious File',
        'T1218.005': 'Mshta',
        'T1218.011': 'Rundll32',
        'T1140': 'Deobfuscate/Decode Files',
        'T1197': 'BITS Jobs',
        'T1486': 'Data Encrypted for Impact',
        'T1055': 'Process Injection',
        'T1003': 'OS Credential Dumping',
    }
    
    def __init__(self, log_dir: str = None):
        """
        Initialize event logger.
        
        Args:
            log_dir: Directory for log files
        """
        if log_dir is None:
            log_dir = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'logs'
            )
        
        self.log_dir = log_dir
        self.log_file = os.path.join(log_dir, 'events.json')
        self.hostname = socket.gethostname()
        
        self._ensure_dir()
    
    def _ensure_dir(self):
        """Ensure log directory exists."""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def _get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        if not file_path or not os.path.exists(file_path):
            return ""
        
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ""
    
    def log_threat(self, 
                   threat_name: str,
                   file_path: str = None,
                   action_taken: str = "LOGGED",
                   mitre_id: str = None,
                   severity: str = "MEDIUM",
                   details: Dict = None) -> Dict:
        """
        Log a security threat event.
        
        Args:
            threat_name: Name of the threat
            file_path: Path to malicious file (if applicable)
            action_taken: Action taken (BLOCKED, QUARANTINED, etc.)
            mitre_id: MITRE ATT&CK technique ID
            severity: CRITICAL, HIGH, MEDIUM, LOW
            details: Additional details dict
            
        Returns:
            The logged event dict
        """
        event = {
            'id': self._generate_id(),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'host': self.hostname,
            'severity': severity,
            'action': action_taken,
            'threat': {
                'name': threat_name,
                'path': file_path,
                'hash': self._get_file_hash(file_path) if file_path else None,
                'mitre_technique': mitre_id,
                'mitre_description': self.MITRE_TECHNIQUES.get(mitre_id, '')
            },
            'details': details or {}
        }
        
        self._append_log(event)
        
        return event
    
    def log_process_event(self,
                          event_type: str,
                          process_name: str,
                          pid: int,
                          command_line: str = None,
                          parent_name: str = None,
                          mitre_id: str = None,
                          action_taken: str = "BLOCKED") -> Dict:
        """
        Log a process-related security event.
        
        Args:
            event_type: Type of event (LOLBIN_ABUSE, MACRO_ATTACK, etc.)
            process_name: Name of the process
            pid: Process ID
            command_line: Command line arguments
            parent_name: Parent process name
            mitre_id: MITRE ATT&CK technique ID
            action_taken: Action taken
            
        Returns:
            The logged event dict
        """
        event = {
            'id': self._generate_id(),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'host': self.hostname,
            'event_type': event_type,
            'severity': 'CRITICAL' if 'ATTACK' in event_type else 'HIGH',
            'action': action_taken,
            'process': {
                'name': process_name,
                'pid': pid,
                'command_line': command_line,
                'parent': parent_name
            },
            'mitre': {
                'technique': mitre_id,
                'description': self.MITRE_TECHNIQUES.get(mitre_id, '')
            }
        }
        
        self._append_log(event)
        
        return event
    
    def log_behavior(self,
                     behavior_type: str,
                     description: str,
                     process_name: str = None,
                     pid: int = None,
                     action_taken: str = "LOGGED") -> Dict:
        """
        Log a behavioral detection event.
        
        Args:
            behavior_type: Type of behavior (RANSOMWARE, INJECTION, etc.)
            description: Description of the behavior
            process_name: Associated process
            pid: Process ID
            action_taken: Action taken
            
        Returns:
            The logged event dict
        """
        event = {
            'id': self._generate_id(),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'host': self.hostname,
            'event_type': f'BEHAVIOR_{behavior_type}',
            'severity': 'CRITICAL' if 'RANSOM' in behavior_type else 'HIGH',
            'action': action_taken,
            'behavior': {
                'type': behavior_type,
                'description': description,
                'process': process_name,
                'pid': pid
            }
        }
        
        self._append_log(event)
        
        return event
    
    def _generate_id(self) -> str:
        """Generate unique event ID."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _append_log(self, event: Dict):
        """Append event to log file."""
        try:
            # Load existing logs
            logs = self.get_all_logs()
            logs.append(event)
            
            # Keep last 1000 events
            if len(logs) > 1000:
                logs = logs[-1000:]
            
            # Write back
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"[Telemetry] Log error: {e}")
    
    def get_all_logs(self) -> List[Dict]:
        """Get all logged events."""
        if not os.path.exists(self.log_file):
            return []
        
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return []
    
    def get_recent(self, count: int = 50) -> List[Dict]:
        """Get most recent events."""
        logs = self.get_all_logs()
        return logs[-count:] if logs else []
    
    def get_by_severity(self, severity: str) -> List[Dict]:
        """Get events by severity level."""
        logs = self.get_all_logs()
        return [e for e in logs if e.get('severity') == severity]
    
    def export_csv(self, output_path: str) -> bool:
        """Export logs to CSV format."""
        import csv
        
        logs = self.get_all_logs()
        
        if not logs:
            return False
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Header
                writer.writerow([
                    'ID', 'Timestamp', 'Host', 'Severity',
                    'Event Type', 'Action', 'Details'
                ])
                
                # Rows
                for event in logs:
                    writer.writerow([
                        event.get('id', ''),
                        event.get('timestamp', ''),
                        event.get('host', ''),
                        event.get('severity', ''),
                        event.get('event_type', event.get('threat', {}).get('name', '')),
                        event.get('action', ''),
                        str(event.get('details', event.get('process', '')))
                    ])
            
            return True
            
        except Exception as e:
            print(f"[Telemetry] CSV export error: {e}")
            return False
    
    def clear_logs(self) -> bool:
        """Clear all logs."""
        try:
            with open(self.log_file, 'w') as f:
                json.dump([], f)
            return True
        except:
            return False
    
    def get_statistics(self) -> Dict:
        """Get log statistics."""
        logs = self.get_all_logs()
        
        stats = {
            'total_events': len(logs),
            'by_severity': {},
            'by_action': {},
            'recent_24h': 0
        }
        
        for event in logs:
            sev = event.get('severity', 'UNKNOWN')
            stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1
            
            action = event.get('action', 'UNKNOWN')
            stats['by_action'][action] = stats['by_action'].get(action, 0) + 1
        
        return stats
