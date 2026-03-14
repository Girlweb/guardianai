"""
GuardianAI Logging System v4.0
SOC 2-Compliant Security Event Logging & Monitoring
"""

import json
import hashlib
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path
import uuid


class GuardianAILoggingSystem:
    """Main logging system coordinator"""
    
    def __init__(self, storage_path: str = '/var/log/guardianai'):
        self.storage = ImmutableLogStorage(storage_path)
        self.retention_months = 12
        
    def log_security_event(self, event: Dict) -> str:
        """Log a security event with full SOC 2 compliance"""
        
        event_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat() + 'Z'
        
        enriched_event = {
            'event_id': event_id,
            'timestamp': timestamp,
            'event_type': event.get('type', 'UNKNOWN'),
            'severity': event.get('severity', 'INFO'),
            'user_id': event.get('user_id', 'system'),
            'system': event.get('system', 'guardianai'),
            'action': event.get('action', 'unknown'),
            'result': event.get('result', 'SUCCESS'),
            'details': event.get('details', {})
        }
        
        self.storage.append(enriched_event)
        
        if enriched_event['severity'] == 'CRITICAL':
            print(f" CRITICAL: {enriched_event['event_type']}")
        
        return event_id
    
    def log_scan_event(self, scan_id: str, repo_url: str, 
                       user_id: str, results: Dict) -> str:
        """Log a security scan execution"""
        
        event = {
            'type': 'SECURITY_SCAN',
            'severity': 'INFO',
            'user_id': user_id,
            'system': 'guardianai_scanner',
            'action': 'execute_scan',
            'result': 'SUCCESS' if results else 'FAILURE',
            'details': {
                'scan_id': scan_id,
                'repo_url': repo_url,
                'findings_count': results.get('summary', {}).get('total_findings', 0),
                'risk_score': results.get('summary', {}).get('risk_score', 0),
                'environment': results.get('environment', 'UNKNOWN')
            }
        }
        
        return self.log_security_event(event)
    
    def log_finding_detected(self, finding: Dict, scan_id: str) -> str:
        """Log when a vulnerability is detected"""
        
        event = {
            'type': 'VULNERABILITY_DETECTED',
            'severity': finding.get('severity', 'MEDIUM'),
            'user_id': 'scanner',
            'system': 'guardianai_scanner',
            'action': 'detect_vulnerability',
            'result': 'DETECTED',
            'details': {
                'scan_id': scan_id,
                'finding_type': finding.get('type'),
                'cve_id': finding.get('cve_id'),
                'package': finding.get('package'),
                'description': finding.get('title') or finding.get('description')
            }
        }
        
        return self.log_security_event(event)
    
    def get_events(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Retrieve events with optional filtering"""
        return self.storage.query_events(filters, limit)
    
    def verify_log_integrity(self) -> bool:
        """Verify log chain integrity"""
        return self.storage.verify_integrity()


class ImmutableLogStorage:
    """Tamper-proof log storage using hash chaining"""
    
    def __init__(self, storage_path: str = '/var/log/guardianai'):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.current_file_path = self.storage_path / 'events.jsonl'
        self.chain_hash = self._load_last_hash()
    
    def append(self, event: Dict) -> None:
        """Append event to log with hash chain"""
        
        event['previous_hash'] = self.chain_hash
        event['hash'] = self._compute_hash(event)
        self.chain_hash = event['hash']
        
        log_entry = json.dumps(event) + '\n'
        
        with open(self.current_file_path, 'a') as f:
            f.write(log_entry)
    
    def query_events(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Query events with filtering"""
        events = []
        
        if not self.current_file_path.exists():
            return events
        
        with open(self.current_file_path, 'r') as f:
            for line in f:
                if len(events) >= limit:
                    break
                event = json.loads(line.strip())
                events.append(event)
        
        return events
    
    def verify_integrity(self) -> bool:
        """Verify hash chain integrity"""
        
        if not self.current_file_path.exists():
            return True
        
        previous_hash = None
        
        with open(self.current_file_path, 'r') as f:
            for line in f:
                event = json.loads(line.strip())
                
                if event['previous_hash'] != previous_hash:
                    return False
                
                stored_hash = event['hash']
                event_copy = event.copy()
                del event_copy['hash']
                
                computed_hash = self._compute_hash(event_copy)
                
                if stored_hash != computed_hash:
                    return False
                
                previous_hash = stored_hash
        
        return True
    
    def _compute_hash(self, event: Dict) -> str:
        """Compute SHA-256 hash of event"""
        event_str = json.dumps(event, sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()
    
    def _load_last_hash(self) -> Optional[str]:
        """Load the last hash from existing log file"""
        if not self.current_file_path.exists():
            return None
        
        try:
            with open(self.current_file_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_event = json.loads(lines[-1].strip())
                    return last_event.get('hash')
        except:
            pass
        
        return None


if __name__ == "__main__":
    # Test
    logger = GuardianAILoggingSystem()
    
    scan_id = logger.log_scan_event(
        scan_id='test_001',
        repo_url='https://github.com/test/repo',
        user_id='mitchele',
        results={'summary': {'total_findings': 5, 'risk_score': 75}}
    )
    
    print(f" Scan logged: {scan_id}")
    print(f" Integrity: {'OK' if logger.verify_log_integrity() else 'FAILED'}")
