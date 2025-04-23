import argparse
import json
import sys
from datetime import datetime
import re
import ipaddress

class AegiswarmAnalyzer:
    def __init__(self):
        self.suspicious_locations = [
            "North Korea", "Russia", "Iran", "China", "Syria"
        ]
        self.suspicious_file_patterns = [
            r'exploit', r'toolkit', r'malware', r'hack', r'crack', r'trojan', 
            r'worm', r'virus', r'ransom', r'backdoor'
        ]
        self.suspicious_process_names = [
            'ssh_brute', 'mal_downloader', 'worm.exe', 'exploit', 'scan', 
            'crack', 'mimikatz', 'pwdump'
        ]
        self.suspicious_protocols = {
            'SMB': [445], 
            'Telnet': [23], 
            'RDP': [3389], 
            'SSH': [22]
        }

    def analyze_logs(self, log_data):
        """Main function to analyze logs using multiple swarm algorithms"""
        if not log_data or 'logs' not in log_data or not log_data['logs']:
            return {
                "overall_status": "safe",
                "threat_score": 0.0,
                "detection_summary": {
                    "aco": 0.0,
                    "pso": 0.0,
                    "abc": 0.0,
                    "firefly": 0.0,
                    "fss": 0.0,
                    "gwo": 0.0
                }
            }
        
        # Run each swarm algorithm on the logs
        aco_score = self.ant_colony_optimization(log_data['logs'])
        pso_score = self.particle_swarm_optimization(log_data['logs'])
        abc_score = self.artificial_bee_colony(log_data['logs'])
        firefly_score = self.firefly_algorithm(log_data['logs'])
        fss_score = self.fish_school_search(log_data['logs'])
        gwo_score = self.grey_wolf_optimizer(log_data['logs'])
        
        # Calculate overall threat score as weighted average
        threat_score = (aco_score * 0.15 + 
                         pso_score * 0.15 + 
                         abc_score * 0.2 + 
                         firefly_score * 0.2 + 
                         fss_score * 0.2 + 
                         gwo_score * 0.1)
        
        # Determine overall status based on threat score
        if threat_score < 0.3:
            overall_status = "safe"
        elif threat_score < 0.7:
            overall_status = "suspicious"
        else:
            overall_status = "threat"
            
        return {
            "overall_status": overall_status,
            "threat_score": threat_score,
            "detection_summary": {
                "aco": aco_score,
                "pso": pso_score,
                "abc": abc_score,
                "firefly": firefly_score,
                "fss": fss_score,
                "gwo": gwo_score
            }
        }
        
    def ant_colony_optimization(self, logs):
        """
        ACO algorithm for log collection & aggregation
        Focuses on finding patterns in log sources and types
        """
        score = 0.0
        
        # Check for logs from suspicious locations
        location_count = sum(1 for log in logs if log.get('location', '') in self.suspicious_locations)
        if location_count > 0:
            score += 0.3 * (location_count / len(logs))
        
        # Check for logs with failed status
        failed_count = sum(1 for log in logs if log.get('status', '').lower() == 'failed')
        if failed_count > 0:
            score += 0.3 * (failed_count / len(logs))
            
        # Check for suspicious process names
        process_count = sum(1 for log in logs 
                          if any(proc in log.get('process_name', '').lower() 
                                for proc in self.suspicious_process_names))
        if process_count > 0:
            score += 0.4 * (process_count / len(logs))
            
        return min(score, 1.0)
        
    def particle_swarm_optimization(self, logs):
        """
        PSO algorithm for real-time threat detection
        Focuses on detecting active threats by monitoring patterns
        """
        score = 0.0
        
        # Check for lateral movement patterns
        lateral_movement = any(log.get('event_type', '') == 'lateral_movement' for log in logs)
        if lateral_movement:
            score += 0.5
        
        # Check for large data transfers
        large_transfers = any(log.get('bytes_received', 0) > 1000000 for log in logs)
        if large_transfers:
            score += 0.4
            
        # Check for suspicious file downloads
        suspicious_downloads = any(log.get('event_type', '') == 'file_download' and
                                 any(re.search(pattern, log.get('filename', '').lower()) 
                                     for pattern in self.suspicious_file_patterns)
                                 for log in logs)
        if suspicious_downloads:
            score += 0.3
            
        return min(score, 1.0)
        
    def artificial_bee_colony(self, logs):
        """
        ABC algorithm for anomaly detection
        Focuses on finding unusual patterns that don't fit normal behavior
        """
        score = 0.0
        
        # Check if multiple failed logins from same IP
        ip_login_attempts = {}
        for log in logs:
            if log.get('event_type', '') == 'login':
                ip = log.get('source_ip', '')
                if ip not in ip_login_attempts:
                    ip_login_attempts[ip] = {'success': 0, 'failed': 0}
                
                if log.get('status', '') == 'failed':
                    ip_login_attempts[ip]['failed'] += 1
                else:
                    ip_login_attempts[ip]['success'] += 1
        
        # Check for brute force patterns
        brute_force_detected = any(attempts['failed'] > 2 for ip, attempts in ip_login_attempts.items())
        if brute_force_detected:
            score += 0.6
            
        # Check for suspicious process names
        if any(log.get('process_name', '').lower() in self.suspicious_process_names for log in logs):
            score += 0.7
            
        # Check for unusual ports or protocols
        unusual_activity = False
        for log in logs:
            protocol = log.get('protocol', '')
            dest_port = log.get('destination_port', 0)
            
            if protocol in self.suspicious_protocols and dest_port in self.suspicious_protocols[protocol]:
                unusual_activity = True
                break
                
        if unusual_activity:
            score += 0.4
            
        return min(score, 1.0)
        
    def firefly_algorithm(self, logs):
        """
        Firefly algorithm for event correlation
        Focuses on finding relationships between events
        """
        score = 0.0
        
        # Check for sequence patterns indicating attack chain
        has_login = any(log.get('event_type', '') == 'login' for log in logs)
        has_download = any(log.get('event_type', '') == 'file_download' for log in logs)
        has_lateral = any(log.get('event_type', '') == 'lateral_movement' for log in logs)
        
        # Full attack chain
        if has_login and has_download and has_lateral:
            score += 0.8
        # Partial attack chains
        elif has_login and has_download:
            score += 0.5
        elif has_download and has_lateral:
            score += 0.6
        elif has_login and has_lateral:
            score += 0.4
            
        # Check for same source IP across multiple events
        source_ips = {}
        for log in logs:
            ip = log.get('source_ip', '')
            if ip:
                if ip not in source_ips:
                    source_ips[ip] = []
                source_ips[ip].append(log.get('event_type', ''))
                
        # If same IP performs multiple types of suspicious activities
        for ip, events in source_ips.items():
            if len(set(events)) > 1:
                score += 0.2 * len(set(events))
                
        return min(score, 1.0)
        
    def fish_school_search(self, logs):
        """
        FSS algorithm for alert prioritization
        Focuses on identifying which events are most important
        """
        score = 0.0
        critical_events = 0
        
        for log in logs:
            event_score = 0
            
            # Check location
            if log.get('location', '') in self.suspicious_locations:
                event_score += 0.3
                
            # Check process name
            proc_name = log.get('process_name', '').lower()
            if any(susp in proc_name for susp in self.suspicious_process_names):
                event_score += 0.4
                
            # Check for file download events with suspicious names
            if log.get('event_type', '') == 'file_download':
                filename = log.get('filename', '').lower()
                if any(re.search(pattern, filename) for pattern in self.suspicious_file_patterns):
                    event_score += 0.5
                    
            # Check for lateral movement
            if log.get('event_type', '') == 'lateral_movement':
                event_score += 0.6
                
            # If individual event is high priority
            if event_score > 0.5:
                critical_events += 1
                
        if critical_events > 0:
            score = min(1.0, critical_events / len(logs) + 0.3)
            
        return min(score, 1.0)
        
    def grey_wolf_optimizer(self, logs):
        """
        GWO algorithm for visualization and dashboard
        Focuses on creating meaningful visualizations from data
        """
        # This algorithm would normally focus on visualization aspects
        # For our analysis, we'll make it focus on detecting APT-like behavior
        score = 0.0
        
        # Check time patterns - APTs usually operate in stages
        if len(logs) >= 3:
            timestamps = [datetime.fromisoformat(log.get('timestamp', '').replace('Z', '+00:00')) 
                         for log in logs if 'timestamp' in log]
            if timestamps:
                # Sort timestamps
                timestamps.sort()
                # Check if events are spread out with some planning
                time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                             for i in range(len(timestamps)-1)]
                
                # APTs often have deliberate pauses between actions
                if any(120 <= diff <= 600 for diff in time_diffs):  # 2-10 minute gaps
                    score += 0.3
        
        # Check for internal network reconnaissance
        internal_ips = 0
        for log in logs:
            dest_ip = log.get('destination_ip', '')
            if dest_ip and self._is_private_ip(dest_ip):
                internal_ips += 1
                
        if internal_ips > 0:
            score += 0.2 * (internal_ips / len(logs))
            
        # Check for evidence of data exfiltration (unusual outbound traffic)
        outbound_data = sum(log.get('bytes_sent', 0) for log in logs)
        if outbound_data > 10000:  # Arbitrary threshold
            score += 0.2
            
        return min(score, 1.0)
    
    def _is_private_ip(self, ip_str):
        """Helper method to check if IP is private/internal"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

def main():
    parser = argparse.ArgumentParser(description='Aegiswarm Security Log Analyzer')
    parser.add_argument('--input', type=str, required=True, help='Input JSON log file path')
    args = parser.parse_args()
    
    try:
        # Load JSON log data
        with open(args.input, 'r') as f:
            log_data = json.load(f)
            
        # Analyze logs
        analyzer = AegiswarmAnalyzer()
        results = analyzer.analyze_logs(log_data)
        
        # Output results as JSON to stdout
        print(json.dumps(results, indent=2))
        
    except FileNotFoundError:
        print(json.dumps({
            "error": "File not found",
            "message": f"The file {args.input} does not exist."
        }), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(json.dumps({
            "error": "Invalid JSON",
            "message": "The input file contains invalid JSON."
        }), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({
            "error": "Analysis failed",
            "message": str(e)
        }), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()