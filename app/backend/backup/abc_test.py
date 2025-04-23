import numpy as np
import random
from typing import Dict, List, Any, Tuple

class ABCLogAnalyzer:
    """
    Artificial Bee Colony algorithm for anomaly detection in security logs.
    
    The ABC algorithm uses the concept of employed bees, onlooker bees, and scout bees
    to search for food sources (solutions). In our security context:
    - Food sources represent potential anomalies/patterns in logs
    - Nectar amount represents the "anomaly score" of a pattern
    - Employed bees search and evaluate initial patterns
    - Onlooker bees focus on promising patterns based on nectar amount
    - Scout bees explore new patterns when existing ones are exhausted
    """

    def __init__(self, colony_size: int = 20, max_iterations: int = 50, limit: int = 10):
        """
        Initialize the ABC log analyzer.
        
        Args:
            colony_size: Number of employed bees (and onlooker bees)
            max_iterations: Maximum number of iterations
            limit: Number of trials before abandoning a solution
        """
        self.colony_size = colony_size
        self.max_iterations = max_iterations
        self.limit = limit
        
        # Define detection patterns and indicators
        self.suspicious_patterns = {
            'location_risk': {
                'high': ['North Korea', 'Russia', 'Iran', 'China', 'Syria'],
                'medium': ['Ukraine', 'Belarus', 'Iraq', 'Pakistan', 'Nigeria']
            },
            'port_risk': {
                'high': [22, 23, 3389, 445, 135, 139, 8080, 1433, 3306],
                'medium': [21, 8443, 5900, 5901, 6667]
            },
            'protocol_risk': {
                'high': ['SMB', 'Telnet', 'RDP', 'SSH'],
                'medium': ['FTP', 'IRC']
            },
            'process_risk': {
                'high': ['ssh_brute', 'mal_downloader', 'worm.exe', 'mimikatz', 'pwdump'],
                'medium': ['scan', 'crack', 'exploit', 'admin']
            },
            'event_risk': {
                'high': ['lateral_movement', 'data_exfiltration', 'privilege_escalation'],
                'medium': ['port_scan', 'brute_force']
            }
        }
        
    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze logs using ABC algorithm to detect anomalies.
        
        Args:
            logs: List of log entries from the JSON file
            
        Returns:
            Dictionary with analysis results including:
            - anomaly score (0-1)
            - detected anomalies
            - confidence level
        """
        if not logs:
            return {
                "algorithm": "abc",
                "anomaly_score": 0.0,
                "detected_anomalies": [],
                "confidence": 0.0
            }
            
        # Extract features for each log entry
        feature_vectors = self._extract_features(logs)
        
        # Initialize food sources (potential anomaly patterns)
        food_sources = self._initialize_food_sources(feature_vectors)
        
        # Track solution improvement and trials
        trials = [0] * len(food_sources)
        best_solution = None
        best_fitness = 0
        
        # Run the ABC algorithm
        for iteration in range(self.max_iterations):
            # Employed Bee Phase
            for i in range(len(food_sources)):
                new_solution = self._produce_new_solution(food_sources, i, feature_vectors)
                new_fitness = self._calculate_fitness(new_solution, feature_vectors)
                current_fitness = self._calculate_fitness(food_sources[i], feature_vectors)
                
                if new_fitness > current_fitness:
                    food_sources[i] = new_solution
                    trials[i] = 0
                else:
                    trials[i] += 1
            
            # Calculate probability values for selection
            fitness_values = [self._calculate_fitness(source, feature_vectors) for source in food_sources]
            sum_fitness = sum(fitness_values)
            probabilities = [fitness / sum_fitness if sum_fitness > 0 else 1.0/len(fitness_values) for fitness in fitness_values]
            
            # Onlooker Bee Phase
            i = 0
            count = 0
            while count < len(food_sources):
                if random.random() < probabilities[i]:
                    count += 1
                    new_solution = self._produce_new_solution(food_sources, i, feature_vectors)
                    new_fitness = self._calculate_fitness(new_solution, feature_vectors)
                    current_fitness = self._calculate_fitness(food_sources[i], feature_vectors)
                    
                    if new_fitness > current_fitness:
                        food_sources[i] = new_solution
                        trials[i] = 0
                    else:
                        trials[i] += 1
                        
                i = (i + 1) % len(food_sources)
            
            # Scout Bee Phase
            for i in range(len(trials)):
                if trials[i] > self.limit:
                    food_sources[i] = self._generate_random_solution(feature_vectors)
                    trials[i] = 0
            
            # Track best solution
            current_best_idx = np.argmax(fitness_values)
            current_best_fitness = fitness_values[current_best_idx]
            
            if best_solution is None or current_best_fitness > best_fitness:
                best_solution = food_sources[current_best_idx]
                best_fitness = current_best_fitness
        
        # Generate results based on best solution
        anomaly_score, detected_anomalies = self._evaluate_best_solution(best_solution, logs, feature_vectors)
        
        return {
            "algorithm": "abc",
            "anomaly_score": anomaly_score,
            "detected_anomalies": detected_anomalies,
            "confidence": best_fitness
        }
        
    def _extract_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """
        Extract numerical features from logs for the ABC algorithm.
        
        Features include:
        - Location risk score
        - Port risk score
        - Protocol risk score
        - Process risk score
        - Event risk score
        - Failed status indicator
        - Bytes transferred ratio
        - Time pattern irregularity
        """
        features = np.zeros((len(logs), 8))
        
        for i, log in enumerate(logs):
            # 1. Location risk
            location = log.get('location', '')
            if location in self.suspicious_patterns['location_risk']['high']:
                features[i, 0] = 1.0
            elif location in self.suspicious_patterns['location_risk']['medium']:
                features[i, 0] = 0.5
                
            # 2. Port risk
            dest_port = log.get('destination_port', 0)
            if dest_port in self.suspicious_patterns['port_risk']['high']:
                features[i, 1] = 1.0
            elif dest_port in self.suspicious_patterns['port_risk']['medium']:
                features[i, 1] = 0.5
                
            # 3. Protocol risk
            protocol = log.get('protocol', '')
            if protocol in self.suspicious_patterns['protocol_risk']['high']:
                features[i, 2] = 1.0
            elif protocol in self.suspicious_patterns['protocol_risk']['medium']:
                features[i, 2] = 0.5
                
            # 4. Process risk
            process = log.get('process_name', '').lower()
            if any(risk in process for risk in self.suspicious_patterns['process_risk']['high']):
                features[i, 3] = 1.0
            elif any(risk in process for risk in self.suspicious_patterns['process_risk']['medium']):
                features[i, 3] = 0.5
                
            # 5. Event risk
            event_type = log.get('event_type', '').lower()
            if event_type in self.suspicious_patterns['event_risk']['high']:
                features[i, 4] = 1.0
            elif event_type in self.suspicious_patterns['event_risk']['medium']:
                features[i, 4] = 0.5
                
            # 6. Failed status
            if log.get('status', '').lower() == 'failed':
                features[i, 5] = 1.0
                
            # 7. Bytes transferred ratio
            bytes_sent = log.get('bytes_sent', 0)
            bytes_received = log.get('bytes_received', 0)
            if bytes_received > 0:
                ratio = bytes_sent / bytes_received if bytes_received > 0 else 0
                if ratio > 5.0:
                    features[i, 6] = 1.0
                elif ratio > 1.0:
                    features[i, 6] = 0.5
            elif bytes_sent > 10000:  # Large outbound with no response
                features[i, 6] = 1.0
                
            # 8. Special filename or username indicators
            filename = log.get('filename', '').lower()
            username = log.get('username', '').lower()
            
            if filename and any(pattern in filename for pattern in ['exploit', 'malware', 'hack', 'backdoor']):
                features[i, 7] = 1.0
            elif username == 'root' or username == 'admin' or username == 'administrator':
                features[i, 7] = 0.7
        
        return features
        
    def _initialize_food_sources(self, feature_vectors: np.ndarray) -> List[np.ndarray]:
        """Initialize food sources (potential anomaly patterns)"""
        food_sources = []
        for _ in range(self.colony_size):
            food_sources.append(self._generate_random_solution(feature_vectors))
        return food_sources
    
    def _generate_random_solution(self, feature_vectors: np.ndarray) -> np.ndarray:
        """Generate a random solution (anomaly pattern weights)"""
        # Generate weights for each feature dimension
        solution = np.random.uniform(0.0, 1.0, size=feature_vectors.shape[1])
        # Normalize so weights sum to 1
        solution /= solution.sum()
        return solution
    
    def _produce_new_solution(self, food_sources: List[np.ndarray], index: int, feature_vectors: np.ndarray) -> np.ndarray:
        """Produce a new solution by modifying the current solution"""
        solution = food_sources[index].copy()
        
        # Select another solution to compare with
        other_index = random.randrange(len(food_sources))
        while other_index == index:
            other_index = random.randrange(len(food_sources))
            
        # Select a dimension to modify
        dimension = random.randrange(len(solution))
        
        # Produce new solution
        phi = random.uniform(-1, 1)
        solution[dimension] += phi * (solution[dimension] - food_sources[other_index][dimension])
        
        # Ensure the solution is valid (all weights between 0 and 1)
        solution[dimension] = max(0.0, min(1.0, solution[dimension]))
        
        # Re-normalize weights
        solution /= solution.sum()
        
        return solution
    
    def _calculate_fitness(self, solution: np.ndarray, feature_vectors: np.ndarray) -> float:
        """
        Calculate fitness of a solution based on how well it identifies anomalies
        
        A good solution should:
        1. Assign high scores to actual anomalies
        2. Create good separation between normal and anomalous logs
        """
        # Apply weights to features
        weighted_features = feature_vectors * solution
        # Sum each row to get anomaly scores for each log entry
        anomaly_scores = weighted_features.sum(axis=1)
        
        if len(anomaly_scores) <= 1:
            return 0.0
            
        # Calculate variance (higher variance = better separation)
        variance = np.var(anomaly_scores)
        
        # Calculate average score (higher average = more anomalies detected)
        avg_score = np.mean(anomaly_scores)
        
        # Calculate skewness (positive skew = few high scores, many low scores)
        skewness = np.mean(((anomaly_scores - avg_score) / np.std(anomaly_scores))**3) if np.std(anomaly_scores) > 0 else 0
        
        # Combine metrics - we want high variance, moderate average, and positive skew
        fitness = (variance * 2.0) + (avg_score * 0.5) + (max(0, skewness) * 1.0)
        
        return fitness
    
    def _evaluate_best_solution(self, solution: np.ndarray, logs: List[Dict[str, Any]], feature_vectors: np.ndarray) -> Tuple[float, List[Dict[str, Any]]]:
        """Evaluate the best solution to produce final results"""
        # Apply weights to features
        weighted_features = feature_vectors * solution
        # Sum each row to get anomaly scores for each log entry
        anomaly_scores = weighted_features.sum(axis=1)
        
        # Normalize scores to 0-1 range if needed
        max_score = np.max(anomaly_scores) if anomaly_scores.size > 0 else 1.0
        if max_score > 0:
            anomaly_scores = anomaly_scores / max_score
        
        # Set threshold for anomaly detection
        threshold = 0.6
        
        # Identify anomalies
        anomaly_indices = np.where(anomaly_scores > threshold)[0]
        detected_anomalies = []
        
        for idx in anomaly_indices:
            log = logs[idx]
            reasons = []
            
            # Determine reasons for flagging this log
            if log.get('location', '') in self.suspicious_patterns['location_risk']['high']:
                reasons.append(f"Suspicious location: {log.get('location')}")
                
            if log.get('destination_port', 0) in self.suspicious_patterns['port_risk']['high']:
                reasons.append(f"High-risk port: {log.get('destination_port')}")
                
            if log.get('protocol', '') in self.suspicious_patterns['protocol_risk']['high']:
                reasons.append(f"Risky protocol: {log.get('protocol')}")
                
            process = log.get('process_name', '').lower()
            for risk in self.suspicious_patterns['process_risk']['high']:
                if risk in process:
                    reasons.append(f"Suspicious process: {log.get('process_name')}")
                    break
                    
            if log.get('status', '').lower() == 'failed':
                reasons.append("Failed operation")
                
            # Add to detected anomalies
            detected_anomalies.append({
                "log_index": int(idx),
                "anomaly_score": float(anomaly_scores[idx]),
                "reasons": reasons,
                "timestamp": log.get('timestamp', ''),
                "source_ip": log.get('source_ip', ''),
                "destination_ip": log.get('destination_ip', '')
            })
        
        # Sort anomalies by score (highest first)
        detected_anomalies.sort(key=lambda x: x["anomaly_score"], reverse=True)
        
        # Calculate overall anomaly score based on:
        # 1. Percentage of logs flagged as anomalous
        # 2. Average score of anomalous logs
        # 3. Maximum anomaly score
        
        anomaly_percentage = len(anomaly_indices) / len(logs) if logs else 0
        avg_anomaly_score = np.mean(anomaly_scores[anomaly_indices]) if len(anomaly_indices) > 0 else 0
        max_anomaly_score = np.max(anomaly_scores) if anomaly_scores.size > 0 else 0
        
        overall_score = (anomaly_percentage * 0.3) + (avg_anomaly_score * 0.4) + (max_anomaly_score * 0.3)
        overall_score = min(1.0, overall_score)
        
        return overall_score, detected_anomalies


# Example usage:
if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        try:
            with open(log_file, 'r') as f:
                log_data = json.load(f)
                
            analyzer = ABCLogAnalyzer()
            results = analyzer.analyze(log_data.get('logs', []))
            
            print(json.dumps(results, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Please provide a log file path")