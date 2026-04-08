"""
Monitoring Agent Module

Observes all cryptographic operations and generates anomaly signals.
Does NOT make decisions or trigger actions.
Does NOT access private keys.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict
from crypto_core.key_manager import KeyManager


logger = logging.getLogger(__name__)


class UsageEvent:
    """Represents a single key usage event."""
    
    def __init__(self, key_id: str, service_id: str, operation: str, timestamp: datetime, success: bool = True, metadata: Optional[Dict] = None):
        self.key_id = key_id
        self.service_id = service_id
        self.operation = operation
        self.timestamp = timestamp
        self.success = success
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            'key_id': self.key_id,
            'service_id': self.service_id,
            'operation': self.operation,
            'timestamp': self.timestamp.isoformat(),
            'success': self.success,
            'metadata': self.metadata
        }


class AnomalySignal:
    """Represents an anomaly signal detected by monitoring."""
    
    def __init__(self, signal_type: str, key_id: str, severity: str, description: str, evidence: Dict[str, Any]):
        self.signal_type = signal_type
        self.key_id = key_id
        self.severity = severity  # 'low', 'medium', 'high', 'critical'
        self.description = description
        self.evidence = evidence
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert signal to dictionary."""
        return {
            'signal_type': self.signal_type,
            'key_id': self.key_id,
            'severity': self.severity,
            'description': self.description,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat()
        }
    
    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.signal_type}: {self.description} (key: {self.key_id})"


class UsageStatistics:
    """Aggregated usage statistics for a key."""
    
    def __init__(self, key_id: str):
        self.key_id = key_id
        self.total_operations = 0
        self.operation_counts = defaultdict(int)  # operation type -> count
        self.success_count = 0
        self.failure_count = 0
        self.first_used: Optional[datetime] = None
        self.last_used: Optional[datetime] = None
        self.service_ids = set()
        self.usage_timeline = []  # List of timestamps
    
    def add_event(self, event: UsageEvent):
        """Add an event to statistics."""
        self.total_operations += 1
        self.operation_counts[event.operation] += 1
        if event.success:
            self.success_count += 1
        else:
            self.failure_count += 1
        
        self.service_ids.add(event.service_id)
        self.usage_timeline.append(event.timestamp)
        
        if self.first_used is None or event.timestamp < self.first_used:
            self.first_used = event.timestamp
        if self.last_used is None or event.timestamp > self.last_used:
            self.last_used = event.timestamp
    
    def get_usage_rate(self, window_minutes: int = 60) -> float:
        """Get operations per minute in the last window."""
        if not self.usage_timeline:
            return 0.0
        
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        recent_ops = [ts for ts in self.usage_timeline if ts >= cutoff]
        return len(recent_ops) / window_minutes if window_minutes > 0 else 0.0
    
    def get_key_age_days(self) -> Optional[float]:
        """Get key age in days."""
        if self.first_used is None:
            return None
        return (datetime.now() - self.first_used).total_seconds() / 86400
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary."""
        return {
            'key_id': self.key_id,
            'total_operations': self.total_operations,
            'operation_counts': dict(self.operation_counts),
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'failure_rate': self.failure_count / self.total_operations if self.total_operations > 0 else 0.0,
            'first_used': self.first_used.isoformat() if self.first_used else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'key_age_days': self.get_key_age_days(),
            'services_using': list(self.service_ids),
            'usage_rate_per_minute': self.get_usage_rate()
        }


class MonitoringAgent:
    """
    Monitoring Agent: Observes cryptographic operations and generates anomaly signals.
    
    Responsibilities:
    - Observe all cryptographic operations from KeyManager
    - Record usage events (key_id, service_id, operation, timestamp)
    - Aggregate usage statistics
    - Generate anomaly signals based on simple rules
    
    Restrictions:
    - Does NOT make decisions
    - Does NOT trigger actions
    - Does NOT access private keys
    """
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.usage_events: List[UsageEvent] = []
        self.statistics: Dict[str, UsageStatistics] = {}
        self.anomaly_signals: List[AnomalySignal] = []
        
        # Anomaly detection thresholds (configurable)
        self.thresholds = {
            'max_usage_count': 1000,  # Alert if key used more than this
            'max_age_days': 90,  # Alert if key older than this
            'max_usage_rate_per_minute': 10.0,  # Alert if usage rate exceeds this
            'max_failure_rate': 0.05,  # Alert if failure rate exceeds 5%
            'min_operations_for_analysis': 10  # Minimum operations before analyzing
        }
        
        logger.info("Monitoring Agent initialized")
    
    def _extract_service_id(self, key_id: str) -> str:
        """
        Extract service ID from key ID.
        
        Key IDs follow pattern: {service_name}-{purpose}-key-v1
        Example: "web-api-signing-key-v1" -> "web-api"
        """
        parts = key_id.split('-')
        if len(parts) >= 2:
            # Take everything before the last 3 parts (assuming "-key-v1" suffix)
            if parts[-1].startswith('v') and parts[-2] == 'key':
                return '-'.join(parts[:-2])
            # Fallback: take first part
            return parts[0]
        return parts[0] if parts else 'unknown'
    
    def observe_operations(self):
        """
        Observe all operations from KeyManager and record them.
        
        This should be called periodically to capture new operations.
        """
        operation_log = self.key_manager.get_operation_log()
        
        # Process new operations (ones we haven't seen yet)
        existing_count = len(self.usage_events)
        
        for log_entry in operation_log[existing_count:]:
            # Extract information from log entry
            key_id = log_entry.get('key_id', 'unknown')
            operation = log_entry.get('operation', 'unknown')
            timestamp_str = log_entry.get('timestamp', datetime.now().isoformat())
            success = log_entry.get('success', True)
            
            # Parse timestamp
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except:
                timestamp = datetime.now()
            
            # Extract service ID from key ID
            service_id = self._extract_service_id(key_id)
            
            # Create usage event
            event = UsageEvent(
                key_id=key_id,
                service_id=service_id,
                operation=operation,
                timestamp=timestamp,
                success=success,
                metadata={k: v for k, v in log_entry.items() 
                         if k not in ['key_id', 'operation', 'timestamp', 'success']}
            )
            
            self.usage_events.append(event)
            
            # Update statistics
            if key_id not in self.statistics:
                self.statistics[key_id] = UsageStatistics(key_id)
            self.statistics[key_id].add_event(event)
        
        if len(operation_log) > existing_count:
            logger.debug(f"Observed {len(operation_log) - existing_count} new operations")
    
    def detect_anomalies(self) -> List[AnomalySignal]:
        """
        Detect anomalies based on simple rules and thresholds.
        
        Returns:
            List of AnomalySignal objects
        """
        self.observe_operations()  # Ensure we have latest data
        new_signals = []
        
        for key_id, stats in self.statistics.items():
            # Skip if not enough data
            if stats.total_operations < self.thresholds['min_operations_for_analysis']:
                continue
            
            # Check for excessive usage count
            if stats.total_operations > self.thresholds['max_usage_count']:
                signal = AnomalySignal(
                    signal_type='excessive_usage',
                    key_id=key_id,
                    severity='high',
                    description=f"Key has been used {stats.total_operations} times (threshold: {self.thresholds['max_usage_count']})",
                    evidence={
                        'usage_count': stats.total_operations,
                        'threshold': self.thresholds['max_usage_count']
                    }
                )
                new_signals.append(signal)
            
            # Check for old keys
            key_age = stats.get_key_age_days()
            if key_age and key_age > self.thresholds['max_age_days']:
                signal = AnomalySignal(
                    signal_type='key_age',
                    key_id=key_id,
                    severity='medium',
                    description=f"Key is {key_age:.1f} days old (threshold: {self.thresholds['max_age_days']} days)",
                    evidence={
                        'age_days': key_age,
                        'threshold_days': self.thresholds['max_age_days']
                    }
                )
                new_signals.append(signal)
            
            # Check for high usage rate
            usage_rate = stats.get_usage_rate()
            if usage_rate > self.thresholds['max_usage_rate_per_minute']:
                signal = AnomalySignal(
                    signal_type='high_usage_rate',
                    key_id=key_id,
                    severity='medium',
                    description=f"Key usage rate is {usage_rate:.2f} ops/min (threshold: {self.thresholds['max_usage_rate_per_minute']} ops/min)",
                    evidence={
                        'usage_rate': usage_rate,
                        'threshold': self.thresholds['max_usage_rate_per_minute']
                    }
                )
                new_signals.append(signal)
            
            # Check for high failure rate
            failure_rate = stats.failure_count / stats.total_operations if stats.total_operations > 0 else 0.0
            if failure_rate > self.thresholds['max_failure_rate']:
                signal = AnomalySignal(
                    signal_type='high_failure_rate',
                    key_id=key_id,
                    severity='critical',
                    description=f"Key has {failure_rate*100:.1f}% failure rate (threshold: {self.thresholds['max_failure_rate']*100}%)",
                    evidence={
                        'failure_rate': failure_rate,
                        'failure_count': stats.failure_count,
                        'total_operations': stats.total_operations,
                        'threshold': self.thresholds['max_failure_rate']
                    }
                )
                new_signals.append(signal)
        
        # Add new signals to the list (avoid duplicates)
        existing_signal_keys = {(s.signal_type, s.key_id) for s in self.anomaly_signals}
        for signal in new_signals:
            signal_key = (signal.signal_type, signal.key_id)
            if signal_key not in existing_signal_keys:
                self.anomaly_signals.append(signal)
                existing_signal_keys.add(signal_key)
        
        return new_signals
    
    def get_usage_statistics(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get usage statistics for a specific key or all keys.
        
        Args:
            key_id: Optional key ID. If None, returns all statistics.
        
        Returns:
            Dictionary of statistics
        """
        self.observe_operations()  # Ensure we have latest data
        
        if key_id:
            if key_id in self.statistics:
                return self.statistics[key_id].to_dict()
            return {}
        else:
            return {k: stats.to_dict() for k, stats in self.statistics.items()}
    
    def get_anomaly_signals(self, key_id: Optional[str] = None, severity: Optional[str] = None) -> List[AnomalySignal]:
        """
        Get anomaly signals, optionally filtered by key_id or severity.
        
        Args:
            key_id: Optional key ID filter
            severity: Optional severity filter ('low', 'medium', 'high', 'critical')
        
        Returns:
            List of AnomalySignal objects
        """
        signals = self.anomaly_signals
        
        if key_id:
            signals = [s for s in signals if s.key_id == key_id]
        
        if severity:
            signals = [s for s in signals if s.severity == severity]
        
        return signals
    
    def get_usage_events(self, key_id: Optional[str] = None, limit: Optional[int] = None) -> List[UsageEvent]:
        """
        Get usage events, optionally filtered by key_id.
        
        Args:
            key_id: Optional key ID filter
            limit: Optional limit on number of events to return
        
        Returns:
            List of UsageEvent objects
        """
        events = self.usage_events
        
        if key_id:
            events = [e for e in events if e.key_id == key_id]
        
        if limit:
            events = events[-limit:]  # Most recent events
        
        return events
    
    def clear_signals(self):
        """Clear all anomaly signals (for testing/reset)."""
        self.anomaly_signals.clear()
        logger.info("Anomaly signals cleared")

