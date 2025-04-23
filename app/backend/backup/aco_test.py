import numpy as np
import random
from typing import Dict, List, Any, Tuple
from datetime import datetime

class ACOLogAnalyzer:
    """
    Ant Colony Optimization algorithm for security log analysis.
    
    This implementation uses ACO to discover patterns in security logs by:
    - Treating logs as nodes in a graph
    - Using ants to find paths between related security events
    - Depositing pheromones on paths that represent significant attack patterns
    - Building clusters of related events that might represent attack chains
    """

    def __init__(self, num_ants: int = 20, iterations: int = 50, 
                 alpha: float = 1.0, beta: float = 2.0, evaporation: float = 0.1,
                 q0: float = 0.9):
        """
        Initialize the ACO log analyzer.
        
        Args:
            num_ants: Number of ants in the colony
            iterations: Number of iterations to run
            alpha: Pheromone importance factor
            beta: Heuristic importance factor
            evaporation: Pheromone evaporation rate
            q0: Probability of choosing best path (vs exploration)
        """
        self.num_ants = num_ants
        self.iterations = iterations
        self.alpha = alpha  # importance of pheromone
        self.beta = beta    # importance of heuristic information
        self.evaporation = evaporation
        self.q0 = q0        # exploitation vs exploration balance
        
        # Define risk factors for different log attributes
        self.risk_factors = {
            'location': {
                'North Korea': 1.0, 'Russia': 0.9, 'Iran': 0.9, 
                'China': 0.8, 'Syria': 0.8, 'Ukraine': 0.7,
                'Belarus': 0.7, 'Iraq': 0.6, 'Pakistan': 0.6
            },
            'protocol': {
                'SMB': 0.9, 'Telnet': 0.9, 'RDP': 0.8, 'SSH': 0.7,
                'FTP': 0.6, 'HTTP': 0.5, 'HTTPS': 0.4
            },
            'port': {
                '445': 0.9,   # SMB
                '23': 0.9,    # Telnet
                '3389': 0.8,  # RDP
                '22': 0.7,    # SSH
                '21': 0.6,    # FTP
                '1433': 0.8,  # MSSQL
                '3306': 0.7,  # MySQL
                '4444': 1.0,  # Metasploit
                '5900': 0.7,  # VNC
                '135': 0.7,   # RPC
                '139': 0.7    # NetBIOS
            },
            'event_type': {
                'lateral_movement': 1.0,
                'data_exfiltration': 0.9,
                'privilege_escalation': 0.9,
                'file_download': 0.8,
                'port_scan': 0.7,
                'login': 0.6
            },
            'process': {
                'ssh_brute': 0.9,
                'mal_downloader': 0.9,
                'worm.exe': 1.0,
                'mimikatz': 1.0,
                'pwdump': 0.9,
                'scan': 0.7,
                'crack': 0.8,
                'exploit': 0.8
            }
        }
        
        self.suspicious_file_patterns = [
            'exe', 'bat', 'ps1', 'sh', 'py', 'pl', 'js',
            'exploit', 'tool', 'malware', 'hack', 'crack',
            'trojan', 'worm', 'virus', 'ransom', 'backdoor'
        ]

    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze logs using ACO to find patterns and anomalies.
        
        Args:
            logs: List of log entries from the JSON file
            
        Returns:
            Dictionary with analysis results
        """
        if not logs:
            return {
                "algorithm": "aco",
                "threat_score": 0.0,
                "clusters": [],
                "attack_patterns": [],
                "most_suspicious_logs": []
            }
            
        # Preprocess logs
        processed_logs = self._preprocess_logs(logs)
        
        # Calculate initial node attractiveness based on individual log risk
        node_attractiveness = self._calculate_node_attractiveness(processed_logs)
        
        # Initialize pheromone matrix
        n_logs = len(processed_logs)
        pheromones = np.ones((n_logs, n_logs)) * 0.1
        
        # Initialize best path and score
        best_path = []
        best_score = 0
        
        # Main ACO loop
        for iteration in range(self.iterations):
            all_paths = []
            all_scores = []
            
            # For each ant
            for ant in range(self.num_ants):
                # Select starting node (weighted by node attractiveness)
                current_node = self._select_starting_node(node_attractiveness)
                path = [current_node]
                visited = set([current_node])
                path_score = node_attractiveness[current_node]
                
                # Build path
                while len(path) < min(n_logs, 10):  # Limit path length
                    next_node = self._select_next_node(
                        current_node, visited, pheromones, node_attractiveness
                    )
                    
                    if next_node is None:
                        break
                        
                    path.append(next_node)
                    visited.add(next_node)
                    
                    # Calculate heuristic proximity between current and next node
                    proximity = self._calculate_proximity(
                        processed_logs[current_node], processed_logs[next_node]
                    )
                    
                    path_score += node_attractiveness[next_node] * proximity
                    current_node = next_node
                
                all_paths.append(path)
                all_scores.append(path_score / len(path) if path else 0)
            
            # Update best path
            best_ant = np.argmax(all_scores)
            if all_scores[best_ant] > best_score:
                best_path = all_paths[best_ant]
                best_score = all_scores[best_ant]
            
            # Update pheromones - evaporation
            pheromones = pheromones * (1 - self.evaporation)
            
            # Update pheromones - deposit
            for ant_idx, path in enumerate(all_paths):
                score = all_scores[ant_idx]
                for i in range(len(path) - 1):
                    pheromones[path[i], path[i+1]] += score
                    pheromones[path[i+1], path[i]] += score  # Symmetric
        
        # Extract final results
        clusters = self._extract_clusters(pheromones, processed_logs, threshold=0.5)
        attack_patterns = self._identify_attack_patterns(clusters, processed_logs)
        suspicious_logs = self._extract_suspicious_logs(node_attractiveness, processed_logs)
        threat_score = self._calculate_threat_score(clusters, attack_patterns, suspicious_logs)
        
        return {
            "algorithm": "aco",
            "threat_score": threat_score,
            "clusters": clusters,
            "attack_patterns": attack_patterns,
            "most_suspicious_logs": suspicious_logs
        }

    def _preprocess_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Preprocess logs to extract and normalize relevant features"""
        processed = []
        
        for log in logs:
            processed_log = {
                'original_index': len(processed),
                'timestamp': log.get('timestamp', ''),
                'source_ip': log.get('source_ip', ''),
                'destination_ip': log.get('destination_ip', ''),
                'protocol': log.get('protocol', ''),
                'port': str(log.get('destination_port', '')),
                'event_type': log.get('event_type', ''),
                'status': log.get('status', ''),
                'location': log.get('location', ''),
                'process': log.get('process_name', ''),
                'filename': log.get('filename', ''),
                'username': log.get('username', ''),
                'bytes_sent': log.get('bytes_sent', 0),
                'bytes_received': log.get('bytes_received', 0)
            }
            
            # Try to convert timestamp to datetime object
            try:
                # Handle ISO format with Z for UTC
                if processed_log['timestamp'].endswith('Z'):
                    processed_log['timestamp'] = processed_log['timestamp'][:-1] + '+00:00'
                processed_log['datetime'] = datetime.fromisoformat(processed_log['timestamp'])
            except (ValueError, TypeError):
                # If conversion fails, use current time
                processed_log['datetime'] = datetime.now()
            
            processed.append(processed_log)
        
        # Sort by timestamp if available
        processed.sort(key=lambda x: x['datetime'])
        
        return processed

    def _calculate_node_attractiveness(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """Calculate the attractiveness of each log entry as a node"""
        attractiveness = np.zeros(len(logs))
        
        for i, log in enumerate(logs):
            score = 0.0
            
            # Location risk
            location = log['location']
            if location in self.risk_factors['location']:
                score += self.risk_factors['location'][location]
            
            # Protocol risk
            protocol = log['protocol']
            if protocol in self.risk_factors['protocol']:
                score += self.risk_factors['protocol'][protocol]
            
            # Port risk
            port = log['port']
            if port in self.risk_factors['port']:
                score += self.risk_factors['port'][port]
            
            # Event type risk
            event_type = log['event_type']
            if event_type in self.risk_factors['event_type']:
                score += self.risk_factors['event_type'][event_type]
            
            # Process risk
            process = log['process']
            for risk_process, risk_score in self.risk_factors['process'].items():
                if risk_process in process.lower():
                    score += risk_score
                    break
            
            # Failed status
            if log['status'].lower() == 'failed':
                score += 0.5
            
            # Suspicious files
            filename = log['filename'].lower()
            if filename:
                for pattern in self.suspicious_file_patterns:
                    if pattern in filename:
                        score += 0.7
                        break
            
            # Normalize to 0-1 range
            attractiveness[i] = min(1.0, score / 5.0)
        
        return attractiveness

    def _select_starting_node(self, attractiveness: np.ndarray) -> int:
        """Select a starting node for an ant, weighted by attractiveness"""
        if np.sum(attractiveness) == 0:
            return random.randint(0, len(attractiveness) - 1)
            
        probs = attractiveness / np.sum(attractiveness)
        return np.random.choice(range(len(attractiveness)), p=probs)

    def _select_next_node(self, current: int, visited: set, pheromones: np.ndarray, 
                          attractiveness: np.ndarray) -> int:
        """Select the next node for an ant to visit"""
        n = len(attractiveness)
        unvisited = [i for i in range(n) if i not in visited]
        
        if not unvisited:
            return None
        
        # Calculate transition probabilities
        probabilities = np.zeros(len(unvisited))
        
        for idx, node in enumerate(unvisited):
            # Pheromone level
            tau = pheromones[current, node]
            # Heuristic information
            eta = attractiveness[node]
            
            probabilities[idx] = (tau ** self.alpha) * (eta ** self.beta)
        
        # Normalize probabilities
        if np.sum(probabilities) > 0:
            probabilities = probabilities / np.sum(probabilities)
        else:
            probabilities = np.ones_like(probabilities) / len(probabilities)
        
        # Exploitation vs exploration
        if random.random() < self.q0:
            # Exploitation: choose best
            best_idx = np.argmax(probabilities)
            return unvisited[best_idx]
        else:
            # Exploration: choose randomly according to probabilities
            return np.random.choice(unvisited, p=probabilities)

    def _calculate_proximity(self, log1: Dict[str, Any], log2: Dict[str, Any]) -> float:
        """Calculate how closely related two log entries are"""
        proximity = 0.0
        
        # Same source IP
        if log1['source_ip'] and log1['source_ip'] == log2['source_ip']:
            proximity += 0.3
        
        # Same destination IP
        if log1['destination_ip'] and log1['destination_ip'] == log2['destination_ip']:
            proximity += 0.3
        
        # Same protocol
        if log1['protocol'] and log1['protocol'] == log2['protocol']:
            proximity += 0.1
        
        # Same location
        if log1['location'] and log1['location'] == log2['location']:
            proximity += 0.2
        
        # Time proximity (events close in time)
        time_diff = (log2['datetime'] - log1['datetime']).total_seconds()
        if 0 <= time_diff <= 300:  # Within 5 minutes
            proximity += 0.3
        elif 300 < time_diff <= 1800:  # Within 30 minutes
            proximity += 0.1
            
        # Sequential attack pattern
        event_sequence = {
            ('login', 'file_download'): 0.4,
            ('file_download', 'lateral_movement'): 0.5,
            ('login', 'lateral_movement'): 0.3,
            ('port_scan', 'login'): 0.3,
            ('port_scan', 'lateral_movement'): 0.3
        }
        
        key = (log1['event_type'], log2['event_type'])
        if key in event_sequence:
            proximity += event_sequence[key]
            
        # Source to destination connection
        if log1['destination_ip'] and log1['destination_ip'] == log2['source_ip']:
            proximity += 0.5
            
        # Cap at 1.0
        return min(1.0, proximity)

    def _extract_clusters(self, pheromones: np.ndarray, logs: List[Dict[str, Any]], 
                          threshold: float = 0.5) -> List[Dict[str, Any]]:
        """Extract clusters of related logs based on pheromone levels"""
        n = len(logs)
        visited = set()
        clusters = []
        
        for i in range(n):
            if i in visited:
                continue
                
            cluster = [i]
            visited.add(i)
            
            # Find connected logs based on pheromone levels
            for j in range(n):
                if j != i and j not in visited and pheromones[i, j] > threshold:
                    cluster.append(j)
                    visited.add(j)
            
            if len(cluster) > 1:  # Only consider clusters with multiple logs
                # Calculate cluster risk score
                risk_score = 0.0
                for idx in cluster:
                    if logs[idx]['status'].lower() == 'failed':
                        risk_score += 0.3
                    if logs[idx]['location'] in self.risk_factors['location']:
                        risk_score += self.risk_factors['location'][logs[idx]['location']]
                    if logs[idx]['event_type'] in self.risk_factors['event_type']:
                        risk_score += self.risk_factors['event_type'][logs[idx]['event_type']]
                
                risk_score = min(1.0, risk_score / len(cluster))
                
                clusters.append({
                    'log_indices': cluster,
                    'risk_score': float(risk_score),
                    'source_ip': logs[cluster[0]]['source_ip'],
                    'size': len(cluster)
                })
        
        # Sort clusters by risk score
        clusters.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return clusters

    def _identify_attack_patterns(self, clusters: List[Dict[str, Any]], 
                                  logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potential attack patterns in the clusters"""
        attack_patterns = []
        
        for cluster in clusters:
            cluster_logs = [logs[i] for i in cluster['log_indices']]
            
            # Check for patterns
            has_failed_login = any(log['event_type'] == 'login' and log['status'] == 'failed' 
                                  for log in cluster_logs)
            has_download = any(log['event_type'] == 'file_download' for log in cluster_logs)
            has_lateral = any(log['event_type'] == 'lateral_movement' for log in cluster_logs)
            
            # Suspicious process names
            suspicious_process = any(
                any(risk_proc in log['process'].lower() 
                    for risk_proc in self.risk_factors['process']) 
                for log in cluster_logs if log['process']
            )
            
            # Check if pattern matches known attack techniques
            pattern_name = None
            severity = 0.0
            
            if has_failed_login and has_download and has_lateral:
                pattern_name = "Complete Attack Chain"
                severity = 0.9
            elif has_download and has_lateral:
                pattern_name = "Malware Spread"
                severity = 0.7
            elif has_failed_login and suspicious_process:
                pattern_name = "Brute Force Attempt"
                severity = 0.6
            elif has_lateral:
                pattern_name = "Lateral Movement"
                severity = 0.7
            elif has_download and suspicious_process:
                pattern_name = "Malware Download"
                severity = 0.6
            
            if pattern_name:
                attack_patterns.append({
                    'pattern_name': pattern_name,
                    'severity': severity,
                    'cluster_id': clusters.index(cluster),
                    'log_indices': cluster['log_indices']
                })
        
        # Sort by severity
        attack_patterns.sort(key=lambda x: x['severity'], reverse=True)
        
        return attack_patterns

    def _extract_suspicious_logs(self, attractiveness: np.ndarray, 
                                logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract the most suspicious individual logs"""
        indices = np.argsort(attractiveness)[::-1][:5]  # Top 5 most suspicious
        
        suspicious_logs = []
        for idx in indices:
            if attractiveness[idx] > 0.3:  # Only include if reasonably suspicious
                suspicious_logs.append({
                    'index': int(idx),
                    'attractiveness': float(attractiveness[idx]),
                    'source_ip': logs[idx]['source_ip'],
                    'event_type': logs[idx]['event_type'],
                    'destination_ip': logs[idx]['destination_ip'],
                    'timestamp': logs[idx]['timestamp'],
                    'location': logs[idx]['location'],
                    'process': logs[idx]['process']
                })
        
        return suspicious_logs

    def _calculate_threat_score(self, clusters: List[Dict[str, Any]], 
                              attack_patterns: List[Dict[str, Any]],
                              suspicious_logs: List[Dict[str, Any]]) -> float:
        """Calculate an overall threat score based on all analysis"""
        score = 0.0
        
        # Contribution from clusters
        if clusters:
            max_cluster_score = max(cluster['risk_score'] for cluster in clusters)
            score += max_cluster_score * 0.4  # 40% weight
        
        # Contribution from attack patterns
        if attack_patterns:
            max_pattern_severity = max(pattern['severity'] for pattern in attack_patterns)
            score += max_pattern_severity * 0.4  # 40% weight
        
        # Contribution from individual suspicious logs
        if suspicious_logs:
            max_log_score = max(log['attractiveness'] for log in suspicious_logs)
            score += max_log_score * 0.2  # 20% weight
        
        return float(min(1.0, score))


# Example usage:
if __name__ == "__main__":
    import json
    import sys
    
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
        try:
            with open(log_file, 'r') as f:
                log_data = json.load(f)
                
            analyzer = ACOLogAnalyzer()
            results = analyzer.analyze(log_data.get('logs', []))
            
            print(json.dumps(results, indent=2))
            
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Please provide a log file path")