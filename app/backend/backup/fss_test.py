import numpy as np
import random
from typing import Dict, List, Any, Tuple
from datetime import datetime

class FSSLogAnalyzer:
    """
    Fish School Search algorithm for security log analysis.
    
    The FSS algorithm uses the concept of collective fish behavior to search for
    optimal solutions. In our security context:
    - Fish represent potential rule sets for anomaly detection
    - Fish position is a vector of weights for different security indicators
    - Fish weight represents the quality of the detection rules
    - Fish movement is guided by individual and collective success
    """

    def __init__(self, school_size: int = 30, iterations: int = 50, 
                 step_ind_init: float = 0.1, step_ind_final: float = 0.001,
                 step_vol_init: float = 0.1, step_vol_final: float = 0.01,
                 step_col: float = 0.1, weight_scale: float = 10.0):
        """
        Initialize the FSS log analyzer.
        
        Args:
            school_size: Number of fish (solution candidates)
            iterations: Number of iterations to run
            step_ind_init: Initial individual movement step size
            step_ind_final: Final individual movement step size
            step_vol_init: Initial volitive movement step size
            step_vol_final: Final volitive movement step size
            step_col: Collective movement step size
            weight_scale: Maximum fish weight
        """
        self.school_size = school_size
        self.iterations = iterations
        self.step_ind_init = step_ind_init
        self.step_ind_final = step_ind_final
        self.step_vol_init = step_vol_init
        self.step_vol_final = step_vol_final
        self.step_col = step_col
        self.weight_scale = weight_scale
        
        # Security feature dimensions (for fish positions)
        self.dimensions = 12  # Number of security features to consider
        
        # Define security indicator patterns and weights
        self.security_indicators = {
            'high_risk_locations': [
                'North Korea', 'Russia', 'Iran', 'China', 'Syria'
            ],
            'medium_risk_locations': [
                'Ukraine', 'Belarus', 'Vietnam', 'Nigeria', 'Brazil'
            ],
            'high_risk_ports': [
                22, 23, 445, 3389, 135, 139, 1433, 4444
            ],
            'high_risk_protocols': [
                'SMB', 'Telnet', 'RDP', 'SSH', 'FTP'
            ],
            'suspicious_processes': [
                'ssh_brute', 'mal_downloader', 'worm.exe', 'exploit', 
                'mimikatz', 'pwdump', 'scan', 'crack'
            ],
            'suspicious_file_patterns': [
                'exploit', 'toolkit', 'malware', 'hack', 'crack', 'trojan', 
                'worm', 'virus', 'ransom', 'backdoor'
            ]
        }

    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze logs using Fish School Search to detect security anomalies.
        
        Args:
            logs: List of log entries from the JSON file
            
        Returns:
            Dictionary with analysis results
        """
        if not logs:
            return {
                "algorithm": "fss",
                "anomaly_score": 0.0,
                "priority_events": [],
                "feature_importance": {},
                "risk_factors": []
            }
            
        # Extract features from logs
        features, log_indices = self._extract_features(logs)
        
        if features.size == 0:  # No valid features extracted
            return {
                "algorithm": "fss",
                "anomaly_score": 0.0,
                "priority_events": [],
                "feature_importance": {},
                "risk_factors": []
            }
        
        # Initialize fish school
        positions = np.random.uniform(0, 1, (self.school_size, self.dimensions))
        weights = np.ones(self.school_size) * (self.weight_scale / 2)
        best_position = None
        best_fitness = 0
        
        # FSS main loop
        for iteration in range(self.iterations):
            # Calculate current step sizes using linear decay
            progress = iteration / self.iterations
            step_ind = self.step_ind_init - progress * (self.step_ind_init - self.step_ind_final)
            step_vol = self.step_vol_init - progress * (self.step_vol_init - self.step_vol_final)
            
            #------------------
            # Individual Movement
            #------------------
            
            # Evaluate all fish and move them individually
            fitness_values = np.zeros(self.school_size)
            new_positions = np.copy(positions)
            
            for i in range(self.school_size):
                # Generate random direction for individual movement
                direction = np.random.uniform(-1, 1, self.dimensions)
                direction = direction / np.linalg.norm(direction) if np.linalg.norm(direction) > 0 else direction
                
                # Try moving in the random direction
                test_position = positions[i] + direction * step_ind
                test_position = np.clip(test_position, 0, 1)  # Keep within bounds
                
                # Evaluate current and new positions
                current_fitness = self._evaluate_fitness(positions[i], features)
                new_fitness = self._evaluate_fitness(test_position, features)
                
                # Update position if new one is better
                if new_fitness > current_fitness:
                    new_positions[i] = test_position
                    fitness_values[i] = new_fitness
                else:
                    fitness_values[i] = current_fitness
                
                # Update best position if needed
                if fitness_values[i] > best_fitness:
                    best_fitness = fitness_values[i]
                    best_position = np.copy(new_positions[i])
            
            # Apply individual movements
            positions = new_positions
            
            #------------------
            # Calculate Barycenter
            #------------------
            
            # Weight update based on fitness improvement
            weight_deltas = np.zeros(self.school_size)
            for i in range(self.school_size):
                # Weight increases if position improved fitness
                prev_fitness = self._evaluate_fitness(positions[i], features)
                new_fitness = fitness_values[i]
                weight_deltas[i] = new_fitness - prev_fitness
            
            # Update weights
            weights = weights + weight_deltas
            weights = np.clip(weights, 1.0, self.weight_scale)  # Keep within range
            
            # Calculate barycenter (weighted center of mass)
            total_weight = np.sum(weights)
            if total_weight > 0:
                weighted_positions = positions * weights[:, np.newaxis]
                barycenter = np.sum(weighted_positions, axis=0) / total_weight
            else:
                barycenter = np.mean(positions, axis=0)
            
            #------------------
            # Collective-Instinctive Movement
            #------------------
            
            # Calculate collective direction as weighted sum of individual movements
            if np.sum(weight_deltas) > 0:
                col_direction = np.sum(
                    (new_positions - positions) * weight_deltas[:, np.newaxis], axis=0
                ) / np.sum(weight_deltas)
            else:
                col_direction = np.zeros(self.dimensions)
            
            # Apply collective movement to all fish
            if np.linalg.norm(col_direction) > 0:
                col_direction = col_direction / np.linalg.norm(col_direction)
                positions = positions + col_direction * self.step_col
                positions = np.clip(positions, 0, 1)  # Keep within bounds
            
            #------------------
            # Collective-Volitive Movement
            #------------------
            
            # Calculate school weight
            total_weight = np.sum(weights)
            prev_total_weight = total_weight - np.sum(weight_deltas)
            
            # Determine if school is expanding or contracting
            if total_weight > prev_total_weight:
                # Expansion - move away from barycenter
                for i in range(self.school_size):
                    direction = positions[i] - barycenter
                    if np.linalg.norm(direction) > 0:
                        direction = direction / np.linalg.norm(direction)
                        positions[i] = positions[i] + direction * step_vol
            else:
                # Contraction - move toward barycenter
                for i in range(self.school_size):
                    direction = barycenter - positions[i]
                    if np.linalg.norm(direction) > 0:
                        direction = direction / np.linalg.norm(direction)
                        positions[i] = positions[i] + direction * step_vol
            
            # Ensure positions stay within bounds
            positions = np.clip(positions, 0, 1)
        
        # Use best fish position for final analysis
        if best_position is None:
            best_idx = np.argmax(fitness_values)
            best_position = positions[best_idx]
            best_fitness = fitness_values[best_idx]
        
        # Generate final analysis results
        anomaly_scores = self._calculate_anomaly_scores(best_position, features)
        
        # Identify priority events
        priority_threshold = 0.6
        priority_indices = np.where(anomaly_scores > priority_threshold)[0]
        priority_events = []
        
        for idx in priority_indices:
            log_index = log_indices[idx]
            log = logs[log_index]
            reasons = self._determine_anomaly_reasons(log, best_position)
            
            priority_events.append({
                "log_index": int(log_index),
                "score": float(anomaly_scores[idx]),
                "timestamp": log.get("timestamp", ""),
                "source_ip": log.get("source_ip", ""),
                "destination_ip": log.get("destination_ip", ""),
                "event_type": log.get("event_type", ""),
                "reasons": reasons
            })
        
        # Sort priority events by score
        priority_events.sort(key=lambda x: x["score"], reverse=True)
        
        # Calculate feature importance from best fish position
        feature_names = [
            "high_risk_location", "medium_risk_location", "high_risk_port",
            "high_risk_protocol", "suspicious_process", "suspicious_file",
            "failed_status", "large_transfer", "repeated_login",
            "unusual_time", "sensitive_action", "unusual_connection"
        ]
        
        # Calculate normalized feature importance
        feature_importance = {}
        for i, feature in enumerate(feature_names):
            feature_importance[feature] = float(best_position[i])
        
        # Calculate overall anomaly score based on:
        # 1. Maximum individual anomaly score
        # 2. Percentage of logs above threshold
        # 3. Best fitness value
        
        max_anomaly = np.max(anomaly_scores) if anomaly_scores.size > 0 else 0
        perc_anomalous = len(priority_indices) / len(logs) if logs else 0
        
        overall_anomaly_score = 0.5 * max_anomaly + 0.3 * perc_anomalous + 0.2 * best_fitness
        overall_anomaly_score = min(1.0, overall_anomaly_score)
        
        # Extract top risk factors
        risk_factors = self._extract_risk_factors(logs, best_position)
        
        return {
            "algorithm": "fss",
            "anomaly_score": float(overall_anomaly_score),
            "priority_events": priority_events,
            "feature_importance": feature_importance,
            "risk_factors": risk_factors
        }

    def _extract_features(self, logs: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[int]]:
        """Extract features from logs for FSS analysis"""
        features = []
        log_indices = []
        
        for i, log in enumerate(logs):
            # Skip logs with insufficient information
            if not log.get('source_ip') and not log.get('event_type'):
                continue
                
            feature_vector = np.zeros(self.dimensions)
            
            # 1. High-risk location
            location = log.get('location', '')
            if location in self.security_indicators['high_risk_locations']:
                feature_vector[0] = 1.0
            
            # 2. Medium-risk location
            elif location in self.security_indicators['medium_risk_locations']:
                feature_vector[1] = 1.0
            
            # 3. High-risk port
            port = log.get('destination_port', 0)
            if port in self.security_indicators['high_risk_ports']:
                feature_vector[2] = 1.0
            
            # 4. High-risk protocol
            protocol = log.get('protocol', '')
            if protocol in self.security_indicators['high_risk_protocols']:
                feature_vector[3] = 1.0
            
            # 5. Suspicious process
            process = log.get('process_name', '').lower()
            if any(susp in process for susp in self.security_indicators['suspicious_processes']):
                feature_vector[4] = 1.0
            
            # 6. Suspicious file
            filename = log.get('filename', '').lower()
            if any(pattern in filename for pattern in self.security_indicators['suspicious_file_patterns']):
                feature_vector[5] = 1.0
            
            # 7. Failed status
            if log.get('status', '').lower() == 'failed':
                feature_vector[6] = 1.0
            
            # 8. Large data transfer
            bytes_sent = log.get('bytes_sent', 0)
            bytes_received = log.get('bytes_received', 0)
            if bytes_sent > 100000 or bytes_received > 1000000:
                feature_vector[7] = 1.0
            
            # 9. Repeated login attempts (approximate)
            if log.get('event_type') == 'login' and log.get('status', '').lower() == 'failed':
                feature_vector[8] = 1.0
            
            # 10. Unusual time (simplified)
            # In production, you'd check for activity during non-business hours
            feature_vector[9] = 0.0  # Placeholder
            
            # 11. Sensitive action
            if log.get('event_type') in ['lateral_movement', 'data_exfiltration', 'privilege_escalation']:
                feature_vector[10] = 1.0
            
            # 12. Unusual connection
            # Simplified: internal to DMZ or external connections
            src_ip = log.get('source_ip', '')
            dst_ip = log.get('destination_ip', '')
            if (src_ip.startswith('192.168.') and not dst_ip.startswith('192.168.')) or \
               (src_ip.startswith('10.') and not dst_ip.startswith('10.')):
                feature_vector[11] = 1.0
            
            features.append(feature_vector)
            log_indices.append(i)
        
        return np.array(features), log_indices

    def _evaluate_fitness(self, position: np.ndarray, features: np.ndarray) -> float:
        """
        Evaluate fitness of a fish position.
        
        A good fish position should:
        1. Effectively differentiate between normal and anomalous events
        2. Have appropriate weights for important security indicators
        3. Produce reasonable anomaly scores
        """
        if features.shape[0] == 0:
            return 0.0
            
        # Calculate anomaly scores using the fish position as weights
        anomaly_scores = np.dot(features, position)
        
        # Normalize scores to 0-1 range
        if np.max(anomaly_scores) > 0:
            anomaly_scores = anomaly_scores / np.max(anomaly_scores)
        
        # Calculate metrics that define a good anomaly detector
        
        # 1. Variance - higher variance means better separation
        variance = np.var(anomaly_scores)
        
        # 2. Distribution skew - positive skew indicates few high anomalies (good)
        skew = 0.0
        if len(anomaly_scores) > 2:
            mean = np.mean(anomaly_scores)
            std = np.std(anomaly_scores)
            if std > 0:
                skew = np.mean(((anomaly_scores - mean) / std) ** 3)
        
        # 3. Weight balance - reward distributions that prioritize critical indicators
        critical_features = [0, 2, 3, 4, 10]  # Indices of most critical features
        critical_weight_sum = sum(position[i] for i in critical_features)
        weight_balance = critical_weight_sum / sum(position) if sum(position) > 0 else 0
        
        # 4. Score excess - penalize if too many events exceed threshold (false positives)
        threshold = 0.7
        excess_ratio = np.mean(anomaly_scores > threshold)
        excess_penalty = 1.0 - min(1.0, excess_ratio * 5)  # Penalize if > 20% are anomalies
        
        # Combine metrics into fitness
        fitness = (
            variance * 1.0 +                # Separation between normal/anomalous
            max(0, skew) * 0.5 +            # Positive skew is good
            weight_balance * 0.8 +          # Appropriate feature weights
            excess_penalty * 0.7            # Not too many anomalies
        )
        
        return fitness

    def _calculate_anomaly_scores(self, position: np.ndarray, features: np.ndarray) -> np.ndarray:
        """Calculate anomaly scores for all logs using the best fish position"""
        # Calculate raw scores using the position vector as weights
        scores = np.dot(features, position)
        
        # Normalize to 0-1 range
        if np.max(scores) > 0:
            scores = scores / np.max(scores)
        
        return scores

    def _determine_anomaly_reasons(self, log: Dict[str, Any], position: np.ndarray) -> List[str]:
        """Determine reasons why a log entry is anomalous based on the fish position"""
        reasons = []
        
        # Check features that contributed most to the anomaly
        feature_threshold = 0.5  # Only consider features with weights above threshold
        
        # High-risk location
        if position[0] > feature_threshold and log.get('location', '') in self.security_indicators['high_risk_locations']:
            reasons.append(f"High-risk location: {log.get('location', '')}")
        
        # High-risk port
        if position[2] > feature_threshold and log.get('destination_port', 0) in self.security_indicators['high_risk_ports']:
            reasons.append(f"High-risk port: {log.get('destination_port', '')}")
        
        # High-risk protocol
        if position[3] > feature_threshold and log.get('protocol', '') in self.security_indicators['high_risk_protocols']:
            reasons.append(f"Suspicious protocol: {log.get('protocol', '')}")
        
        # Suspicious process
        if position[4] > feature_threshold:
            process = log.get('process_name', '').lower()
            for susp in self.security_indicators['suspicious_processes']:
                if susp in process:
                    reasons.append(f"Suspicious process: {log.get('process_name', '')}")
                    break
        
        # Suspicious file
        if position[5] > feature_threshold:
            filename = log.get('filename', '').lower()
            for pattern in self.security_indicators['suspicious_file_patterns']:
                if pattern in filename:
                    reasons.append(f"Suspicious filename: {log.get('filename', '')}")
                    break
        
        # Failed status
        if position[6] > feature_threshold and log.get('status', '').lower() == 'failed':
            reasons.append("Failed operation")
        
        # Large transfer
        if position[7] > feature_threshold:
            bytes_sent = log.get('bytes_sent', 0)
            bytes_received = log.get('bytes_received', 0)
            if bytes_sent > 100000:
                reasons.append(f"Large outbound transfer: {bytes_sent} bytes")
            if bytes_received > 1000000:
                reasons.append(f"Large inbound transfer: {bytes_received} bytes")
        
        # Sensitive action
        if position[10] > feature_threshold and log.get('event_type') in ['lateral_movement', 'data_exfiltration', 'privilege_escalation']:
            reasons.append(f"Sensitive action: {log.get('event_type', '')}")
        
        return reasons

    def _extract_risk_factors(self, logs: List[Dict[str, Any]], position: np.ndarray) -> List[Dict[str, Any]]:
        """Extract top risk factors identified by the best fish position"""
        risk_factors = []
        
        # Get the top weighted features
        feature_names = [
            "High Risk Location", "Medium Risk Location", "High Risk Port",
            "High Risk Protocol", "Suspicious Process", "Suspicious File",
            "Failed Status", "Large Transfer", "Repeated Login",
            "Unusual Time", "Sensitive Action", "Unusual Connection"
        ]
        
        top_indices = np.argsort(position)[::-1][:5]  # Top 5 features
        
        for idx in top_indices:
            if position[idx] > 0.3:  # Only include significant factors
                # Find example logs that exhibit this factor
                example_logs = []
                
                for i, log in enumerate(logs):
                    # Check if this log demonstrates the current risk factor
                    if idx == 0 and log.get('location', '') in self.security_indicators['high_risk_locations']:
                        example_logs.append(i)
                    elif idx == 1 and log.get('location', '') in self.security_indicators['medium_risk_locations']:
                        example_logs.append(i)
                    elif idx == 2 and log.get('destination_port', 0) in self.security_indicators['high_risk_ports']:
                        example_logs.append(i)
                    elif idx == 3 and log.get('protocol', '') in self.security_indicators['high_risk_protocols']:
                        example_logs.append(i)
                    elif idx == 4:
                        process = log.get('process_name', '').lower()
                        if any(susp in process for susp in self.security_indicators['suspicious_processes']):
                            example_logs.append(i)
                    elif idx == 5:
                        filename = log.get('filename', '').lower()
                        if any(pattern in filename for pattern in self.security_indicators['suspicious_file_patterns']):
                            example_logs.append(i)
                    elif idx == 6 and log.get('status', '').lower() == 'failed':
                        example_logs.append(i)
                    elif idx == 7:
                        bytes_sent = log.get('bytes_sent', 0)
                        bytes_received = log.get('bytes_received', 0)
                        if bytes_sent > 100000 or bytes_received > 1000000:
                            example_logs.append(i)
                    elif idx == 10 and log.get('event_type') in ['lateral_movement', 'data_exfiltration', 'privilege_escalation']:
                        example_logs.append(i)
                
                # Limit examples to 3 max
                example_logs = example_logs[:3]
                
                # Add risk factor to the list
                risk_factors.append({
                    "factor": feature_names[idx],
                    "weight": float(position[idx]),
                    "example_logs": example_logs
                })
        
        return risk_factors


# Example usage:
if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        try:
            with open(log_file, 'r') as f:
                log_data = json.load(f)
                
            analyzer = FSSLogAnalyzer()
            results = analyzer.analyze(log_data.get('logs', []))
            
            print(json.dumps(results, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Please provide a log file path")