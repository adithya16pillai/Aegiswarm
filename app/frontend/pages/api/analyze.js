import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const logData = req.body;
    
    // Save the log data to a temporary file
    const tempFilePath = path.join(process.cwd(), 'temp_logs.json');
    fs.writeFileSync(tempFilePath, JSON.stringify(logData, null, 2));
    
    // For testing purposes, try to use the sample log file if available
    try {
      const samplePath = 'C:\\Users\\adith\\Desktop\\Final Project\\Aegiswarm\\aegiswarm\\data\\sample_log_safe.json';
      if (fs.existsSync(samplePath)) {
        console.log('Using sample log file for reference');
      }
    } catch (e) {
      console.log('Sample log file not accessible:', e.message);
    }
    
    // Analyze logs directly in JavaScript
    const results = analyzeLogs(logData);
    
    // Clean up the temporary file
    if (fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
    }
    
    // Return the results
    return res.status(200).json(results);
    
  } catch (error) {
    console.error('API handler error:', error);
    return res.status(500).json({ error: 'Internal server error', message: error.message });
  }
}

// JavaScript implementation of the log analysis logic
function analyzeLogs(logData) {
  if (!logData || !logData.logs || !Array.isArray(logData.logs) || logData.logs.length === 0) {
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
    };
  }

  const logs = logData.logs;
  console.log(`Analyzing ${logs.length} log entries`);
  
  // Suspicious indicators
  const suspiciousLocations = ["North Korea", "Russia", "Iran", "China", "Syria"];
  const suspiciousFilePatterns = ['exploit', 'toolkit', 'malware', 'hack', 'crack', 'trojan', 'worm', 'virus', 'ransom', 'backdoor'];
  const suspiciousProcessNames = ['ssh_brute', 'mal_downloader', 'worm.exe', 'exploit', 'scan', 'crack', 'mimikatz', 'pwdump'];
  const suspiciousProtocols = {
    'SMB': [445], 
    'Telnet': [23], 
    'RDP': [3389], 
    'SSH': [22]
  };

  // Algorithm scores
  let acoScore = 0;
  let psoScore = 0;
  let abcScore = 0;
  let fireflyScore = 0;
  let fssScore = 0;
  let gwoScore = 0;
  
  // ACO - check for suspicious locations, failed status, suspicious processes
  const suspLocCount = logs.filter(log => suspiciousLocations.includes(log.location || '')).length;
  if (suspLocCount > 0) {
    acoScore += 0.3 * (suspLocCount / logs.length);
  }
  
  const failedCount = logs.filter(log => (log.status || '').toLowerCase() === 'failed').length;
  if (failedCount > 0) {
    acoScore += 0.3 * (failedCount / logs.length);
  }
  
  const suspProcCount = logs.filter(log => {
    const procName = (log.process_name || '').toLowerCase();
    return suspiciousProcessNames.some(p => procName.includes(p));
  }).length;
  if (suspProcCount > 0) {
    acoScore += 0.4 * (suspProcCount / logs.length);
  }
  acoScore = Math.min(acoScore, 1.0);
  
  // PSO - check for lateral movement, large transfers, suspicious downloads
  if (logs.some(log => log.event_type === 'lateral_movement')) {
    psoScore += 0.5;
  }
  
  if (logs.some(log => (log.bytes_received || 0) > 1000000)) {
    psoScore += 0.4;
  }
  
  if (logs.some(log => {
    return log.event_type === 'file_download' && 
      suspiciousFilePatterns.some(pattern => (log.filename || '').toLowerCase().includes(pattern));
  })) {
    psoScore += 0.3;
  }
  psoScore = Math.min(psoScore, 1.0);
  
  // ABC - check for brute force patterns, suspicious processes
  const loginsByIp = {};
  logs.forEach(log => {
    if (log.event_type === 'login') {
      const ip = log.source_ip || '';
      if (!loginsByIp[ip]) loginsByIp[ip] = { success: 0, failed: 0 };
      if (log.status === 'failed') {
        loginsByIp[ip].failed++;
      } else {
        loginsByIp[ip].success++;
      }
    }
  });
  
  if (Object.values(loginsByIp).some(attempts => attempts.failed > 2)) {
    abcScore += 0.6;
  }
  
  if (logs.some(log => suspiciousProcessNames.includes((log.process_name || '').toLowerCase()))) {
    abcScore += 0.7;
  }
  
  if (logs.some(log => {
    const protocol = log.protocol || '';
    const destPort = log.destination_port || 0;
    return suspiciousProtocols[protocol] && suspiciousProtocols[protocol].includes(destPort);
  })) {
    abcScore += 0.4;
  }
  abcScore = Math.min(abcScore, 1.0);
  
  // Firefly - check for attack chains and related events
  const hasLogin = logs.some(log => log.event_type === 'login');
  const hasDownload = logs.some(log => log.event_type === 'file_download');
  const hasLateral = logs.some(log => log.event_type === 'lateral_movement');
  
  if (hasLogin && hasDownload && hasLateral) {
    fireflyScore += 0.8;
  } else if (hasLogin && hasDownload) {
    fireflyScore += 0.5;
  } else if (hasDownload && hasLateral) {
    fireflyScore += 0.6;
  } else if (hasLogin && hasLateral) {
    fireflyScore += 0.4;
  }
  
  const sourceIps = {};
  logs.forEach(log => {
    const ip = log.source_ip || '';
    if (ip) {
      if (!sourceIps[ip]) sourceIps[ip] = [];
      sourceIps[ip].push(log.event_type || '');
    }
  });
  
  Object.values(sourceIps).forEach(events => {
    const uniqueEvents = new Set(events);
    if (uniqueEvents.size > 1) {
      fireflyScore += 0.2 * uniqueEvents.size;
    }
  });
  fireflyScore = Math.min(fireflyScore, 1.0);
  
  // FSS - check for priority events
  let criticalEvents = 0;
  logs.forEach(log => {
    let eventScore = 0;
    
    if (suspiciousLocations.includes(log.location || '')) {
      eventScore += 0.3;
    }
    
    const procName = (log.process_name || '').toLowerCase();
    if (suspiciousProcessNames.some(p => procName.includes(p))) {
      eventScore += 0.4;
    }
    
    if (log.event_type === 'file_download') {
      const filename = (log.filename || '').toLowerCase();
      if (suspiciousFilePatterns.some(p => filename.includes(p))) {
        eventScore += 0.5;
      }
    }
    
    if (log.event_type === 'lateral_movement') {
      eventScore += 0.6;
    }
    
    if (eventScore > 0.5) {
      criticalEvents++;
    }
  });
  
  if (criticalEvents > 0) {
    fssScore = Math.min(1.0, criticalEvents / logs.length + 0.3);
  }
  
  // GWO - check for APT-like behavior
  // Check for internal network targeting
  const internalIps = logs.filter(log => {
    const ip = log.destination_ip || '';
    return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.');
  }).length;
  
  if (internalIps > 0) {
    gwoScore += 0.2 * (internalIps / logs.length);
  }
  
  // Check for suspicious file downloads
  const suspDownloads = logs.filter(log => {
    return log.event_type === 'file_download' && 
      suspiciousFilePatterns.some(pattern => (log.filename || '').toLowerCase().includes(pattern));
  }).length;
  
  if (suspDownloads > 0) {
    gwoScore += 0.4 * (suspDownloads / logs.length);
  }
  
  // Check for lateral movement
  if (logs.some(log => log.event_type === 'lateral_movement')) {
    gwoScore += 0.4;
  }
  
  gwoScore = Math.min(gwoScore, 1.0);
  
  // Calculate overall threat score (weighted average)
  const threatScore = (
    acoScore * 0.15 + 
    psoScore * 0.15 + 
    abcScore * 0.2 + 
    fireflyScore * 0.2 + 
    fssScore * 0.2 + 
    gwoScore * 0.1
  );
  
  // Determine overall status based on threat score
  let overallStatus;
  if (threatScore < 0.3) {
    overallStatus = 'safe';
  } else if (threatScore < 0.7) {
    overallStatus = 'suspicious';
  } else {
    overallStatus = 'threat';
  }
  
  console.log('Analysis complete:');
  console.log(`- Overall status: ${overallStatus}`);
  console.log(`- Threat score: ${threatScore.toFixed(2)}`);
  
  return {
    "overall_status": overallStatus,
    "threat_score": threatScore,
    "detection_summary": {
      "aco": acoScore,
      "pso": psoScore,
      "abc": abcScore,
      "firefly": fireflyScore,
      "fss": fssScore,
      "gwo": gwoScore
    }
  };
}