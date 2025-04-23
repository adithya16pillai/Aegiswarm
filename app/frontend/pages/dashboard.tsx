import { useState, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import '../styles/globals.css';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('overview');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  
  // Sample data for the dashboard visualizations
  const mockData = {
    threats: {
      total: 147,
      critical: 12,
      high: 37,
      medium: 54,
      low: 44,
    },
    sources: [
      { name: 'Firewall', count: 428, percentage: 42 },
      { name: 'Endpoint Protection', count: 256, percentage: 25 },
      { name: 'Cloud Services', count: 187, percentage: 18 },
      { name: 'Authentication', count: 98, percentage: 10 },
      { name: 'Other', count: 51, percentage: 5 },
    ],
    threatVectors: [
      { type: 'Malware', count: 48 },
      { type: 'Phishing', count: 36 },
      { type: 'Brute Force', count: 27 },
      { type: 'DDoS', count: 14 },
      { type: 'Insider', count: 11 },
      { type: 'Zero Day', count: 5 },
    ],
    anomalyTypes: [
      { type: 'Traffic Spike', count: 32 },
      { type: 'Auth Failure', count: 45 },
      { type: 'Data Exfiltration', count: 12 },
      { type: 'API Abuse', count: 18 },
      { type: 'Privilege Escalation', count: 7 },
    ],
    alerts: [
      { id: 'ALT-3429', source: 'Endpoint', severity: 'critical', time: '11:42:06', description: 'Multiple failed admin login attempts detected on server EXT-004' },
      { id: 'ALT-3428', source: 'Firewall', severity: 'high', time: '11:38:54', description: 'Unusual outbound data transfer from engineering workstation to external IP' },
      { id: 'ALT-3427', source: 'Cloud', severity: 'critical', time: '11:30:17', description: 'S3 bucket permission change detected with public read access' },
      { id: 'ALT-3426', source: 'Auth', severity: 'medium', time: '11:28:35', description: 'User account accessed from previously unseen location' },
      { id: 'ALT-3425', source: 'Endpoint', severity: 'high', time: '11:20:42', description: 'PowerShell execution with encoded command parameters' },
      { id: 'ALT-3424', source: 'Firewall', severity: 'medium', time: '11:15:20', description: 'Connection attempt to known malware C2 server blocked' },
    ],
    liveData: [
      { id: 'LOG-7825', source: '192.168.1.45', type: 'AUTH', message: 'User login successful', time: '11:42:27', status: 'normal' },
      { id: 'LOG-7824', source: '192.168.1.105', type: 'FIREWALL', message: 'Connection blocked', time: '11:42:21', status: 'blocked' },
      { id: 'LOG-7823', source: '192.168.1.22', type: 'ENDPOINT', message: 'Software installed: Chrome 95.0.4638.69', time: '11:42:14', status: 'normal' },
      { id: 'LOG-7822', source: '192.168.1.88', type: 'API', message: 'Rate limit exceeded', time: '11:42:05', status: 'warning' },
      { id: 'LOG-7821', source: '192.168.1.12', type: 'AUTH', message: 'Failed login attempt', time: '11:41:59', status: 'warning' },
      { id: 'LOG-7820', source: '192.168.1.224', type: 'CLOUD', message: 'New resource created', time: '11:41:48', status: 'normal' },
    ]
  };

  // Mock MITRE ATT&CK matrix categories
  const mitreCategories = [
    'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 
    'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
    'Collection', 'Command and Control', 'Exfiltration', 'Impact'
  ];

  // Generate random data for MITRE ATT&CK heatmap
  const mitreTechniques = {};
  mitreCategories.forEach(category => {
    mitreTechniques[category] = Array.from({length: Math.floor(Math.random() * 5) + 2}, (_, i) => ({
      id: `T${Math.floor(1000 + Math.random() * 9000)}`,
      name: `${category} Technique ${i+1}`,
      count: Math.floor(Math.random() * 10),
    }));
  });
  
  // Mock data for top threat countries
  const threatCountries = [
    { code: 'RU', name: 'Russia', count: 1245 },
    { code: 'CN', name: 'China', count: 976 },
    { code: 'US', name: 'United States', count: 724 },
    { code: 'BR', name: 'Brazil', count: 431 },
    { code: 'IN', name: 'India', count: 317 },
    { code: 'KP', name: 'North Korea', count: 276 },
    { code: 'IR', name: 'Iran', count: 203 },
    { code: 'VN', name: 'Vietnam', count: 187 }
  ];
  
  // Add a streaming effect to the live data
  useEffect(() => {
    const newLogInterval = setInterval(() => {
      // In a real app, this would be a WebSocket or SSE connection
    }, 5000);
    
    return () => clearInterval(newLogInterval);
  }, []);

  // Utility function to generate different bar heights for visualization
  const getBarHeight = (value, max = 100) => {
    return `${Math.min((value / max) * 100, 100)}%`;
  };

  return (
    <div className="dashboardContainer">
      <Head>
        <title>aegiswarm | security dashboard</title>
        <meta name="description" content="Real-time security monitoring dashboard" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      {/* Dashboard Sidebar */}
      <aside className={`dashboardSidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
        <div className="sidebarHeader">
          <Link href="/">
            <div className="logo">
              aegis<span className="logoHighlight">warm</span>
            </div>
          </Link>
          <button 
            className="collapseButton" 
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          >
            {sidebarCollapsed ? '→' : '←'}
          </button>
        </div>
        
        <nav className="sidebarNav">
          <ul className="sidebarMenu">
            <li className={activeTab === 'overview' ? 'active' : ''}>
              <button onClick={() => setActiveTab('overview')}>
                <span className="menuIcon">📊</span>
                <span className="menuText">Overview</span>
              </button>
            </li>
            <li className={activeTab === 'threats' ? 'active' : ''}>
              <button onClick={() => setActiveTab('threats')}>
                <span className="menuIcon">⚠️</span>
                <span className="menuText">Active Threats</span>
              </button>
            </li>
            <li className={activeTab === 'anomalies' ? 'active' : ''}>
              <button onClick={() => setActiveTab('anomalies')}>
                <span className="menuIcon">🔍</span>
                <span className="menuText">Anomalies</span>
              </button>
            </li>
            <li className={activeTab === 'alerts' ? 'active' : ''}>
              <button onClick={() => setActiveTab('alerts')}>
                <span className="menuIcon">🔔</span>
                <span className="menuText">Alert Queue</span>
              </button>
            </li>
            <li className={activeTab === 'logs' ? 'active' : ''}>
              <button onClick={() => setActiveTab('logs')}>
                <span className="menuIcon">📝</span>
                <span className="menuText">Live Logs</span>
              </button>
            </li>
          </ul>
        </nav>
        
        <div className="sidebarFooter">
          <div className="systemStatus">
            <div className="statusIndicator green"></div>
            <span>System Operational</span>
          </div>
          <div className="lastUpdated">
            Last updated: {new Date().toLocaleTimeString()}
          </div>
        </div>
      </aside>

      {/* Main Dashboard Content */}
      <main className="dashboardMain">
        <header className="dashboardHeader">
          <h1>Security Dashboard</h1>
          <div className="headerActions">
            <div className="searchContainer">
              <input type="text" placeholder="Search logs, alerts, devices..." />
              <button className="searchButton">🔍</button>
            </div>
            <div className="userProfile">
              <div className="userAvatar">A</div>
              <div className="userName">Admin</div>
            </div>
          </div>
        </header>

        {/* Dashboard Overview */}
        {activeTab === 'overview' && (
          <div className="dashboardContent">
            <div className="overviewStats">
              <div className="statCard">
                <div className="statTitle">Total Threats</div>
                <div className="statValue">{mockData.threats.total}</div>
                <div className="statBreakdown">
                  <span className="criticalTag">{mockData.threats.critical} critical</span>
                  <span className="highTag">{mockData.threats.high} high</span>
                </div>
              </div>
              <div className="statCard">
                <div className="statTitle">Anomaly Score</div>
                <div className="statValue">37.8</div>
                <div className="statTrend up">+5.2 from yesterday</div>
              </div>
              <div className="statCard">
                <div className="statTitle">Detection Rate</div>
                <div className="statValue">98.2%</div>
                <div className="statTrend down">-0.3% from last week</div>
              </div>
              <div className="statCard">
                <div className="statTitle">Logs Processed</div>
                <div className="statValue">3.2M</div>
                <div className="statBreakdown">
                  <span>1,240/sec average</span>
                </div>
              </div>
            </div>
            
            <div className="dashboardGrid">
              {/* Live Data Streams */}
              <div className="dashboardCard wide">
                <div className="cardHeader">
                  <h2>Live Data Streams</h2>
                  <div className="cardActions">
                    <button className="cardAction">Filter</button>
                  </div>
                </div>
                <div className="cardContent">
                  <div className="liveDataStreams">
                    <div className="streamGroup">
                      <h3>Firewalls</h3>
                      <div className="streamVisualization">
                        <div className="streamLine">
                          {[...Array(50)].map((_, i) => (
                            <div 
                              key={i} 
                              className="streamPulse" 
                              style={{ 
                                height: `${Math.max(5, Math.random() * 40)}px`,
                                backgroundColor: `hsl(${220 + Math.random() * 40}deg, 80%, 60%)`
                              }}
                            ></div>
                          ))}
                        </div>
                        <div className="streamStats">
                          <div className="streamCount">1.2k events/min</div>
                          <div className="streamChange up">+8%</div>
                        </div>
                      </div>
                    </div>
                    <div className="streamGroup">
                      <h3>Endpoints</h3>
                      <div className="streamVisualization">
                        <div className="streamLine">
                          {[...Array(50)].map((_, i) => (
                            <div 
                              key={i} 
                              className="streamPulse" 
                              style={{ 
                                height: `${Math.max(5, Math.random() * 35)}px`,
                                backgroundColor: `hsl(${120 + Math.random() * 40}deg, 70%, 50%)`
                              }}
                            ></div>
                          ))}
                        </div>
                        <div className="streamStats">
                          <div className="streamCount">756 events/min</div>
                          <div className="streamChange">+2%</div>
                        </div>
                      </div>
                    </div>
                    <div className="streamGroup">
                      <h3>Cloud Services</h3>
                      <div className="streamVisualization">
                        <div className="streamLine">
                          {[...Array(50)].map((_, i) => (
                            <div 
                              key={i} 
                              className="streamPulse" 
                              style={{ 
                                height: `${Math.max(5, Math.random() * 50)}px`,
                                backgroundColor: `hsl(${280 + Math.random() * 40}deg, 70%, 65%)`
                              }}
                            ></div>
                          ))}
                        </div>
                        <div className="streamStats">
                          <div className="streamCount">845 events/min</div>
                          <div className="streamChange up">+12%</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Top Sources by Volume */}
              <div className="dashboardCard">
                <div className="cardHeader">
                  <h2>Top Sources by Volume</h2>
                  <div className="cardActions">
                    <button className="cardAction">Details</button>
                  </div>
                </div>
                <div className="cardContent">
                  <div className="sourcesChart">
                    {mockData.sources.map((source, index) => (
                      <div className="sourceItem" key={index}>
                        <div className="sourceLabel">{source.name}</div>
                        <div className="sourceBarContainer">
                          <div 
                            className="sourceBar" 
                            style={{ width: `${source.percentage}%` }}
                          ></div>
                          <div className="sourceValue">{source.count}</div>
                        </div>
                        <div className="sourcePercentage">{source.percentage}%</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              
              {/* Active Threats Heatmap */}
              <div className="dashboardCard">
                <div className="cardHeader">
                  <h2>Active Threats Heatmap</h2>
                  <div className="cardActions">
                    <button className="cardAction">Details</button>
                  </div>
                </div>
                <div className="cardContent">
                  <div className="threatHeatmap">
                    <div className="heatmapGrid">
                      {Array.from({ length: 64 }, (_, i) => {
                        const intensity = Math.random();
                        const colorClass = intensity 
                          > 0.8 ? 'critical'
                          : intensity > 0.6 ? 'high'
                          : intensity > 0.3 ? 'medium'
                          : intensity > 0.1 ? 'low'
                          : 'none';
                        
                        return (
                          <div 
                            key={i}
                            className={`heatmapCell ${colorClass}`} 
                            title={`Threat Level: ${colorClass}`}
                          />
                        );
                      })}
                    </div>
                    <div className="heatmapLegend">
                      <div className="legendItem">
                        <div className="legendColor critical"></div>
                        <span>Critical</span>
                      </div>
                      <div className="legendItem">
                        <div className="legendColor high"></div>
                        <span>High</span>
                      </div>
                      <div className="legendItem">
                        <div className="legendColor medium"></div>
                        <span>Medium</span>
                      </div>
                      <div className="legendItem">
                        <div className="legendColor low"></div>
                        <span>Low</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Alert Priority Queue */}
              <div className="dashboardCard wide">
                <div className="cardHeader">
                  <h2>Alert Priority Queue</h2>
                  <div className="cardActions">
                    <button className="cardAction">View All</button>
                  </div>
                </div>
                <div className="cardContent">
                  <div className="alertTable">
                    <div className="tableHeader">
                      <div className="tableCell">ID</div>
                      <div className="tableCell">Source</div>
                      <div className="tableCell">Severity</div>
                      <div className="tableCell">Time</div>
                      <div className="tableCell wide">Description</div>
                    </div>
                    <div className="tableBody">
                      {mockData.alerts.map((alert, index) => (
                        <div className={`tableRow ${alert.severity}`} key={index}>
                          <div className="tableCell">{alert.id}</div>
                          <div className="tableCell">{alert.source}</div>
                          <div className="tableCell">
                            <span className={`severityBadge ${alert.severity}`}>
                              {alert.severity}
                            </span>
                          </div>
                          <div className="tableCell">{alert.time}</div>
                          <div className="tableCell wide">{alert.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              
              {/* MITRE ATT&CK Coverage */}
              <div className="dashboardCard wide">
                <div className="cardHeader">
                  <h2>MITRE ATT&CK Coverage</h2>
                  <div className="cardActions">
                    <button className="cardAction">Details</button>
                  </div>
                </div>
                <div className="cardContent">
                  <div className="mitreMatrix">
                    <div className="mitreCategories">
                      {mitreCategories.map((category, i) => (
                        <div className="mitreCategory" key={i}>
                          <div className="categoryName">{category}</div>
                          <div className="categoryTechniques">
                            {mitreTechniques[category].map((technique, j) => (
                              <div className="technique" key={j}>
                                <span className="techniqueId">{technique.id}</span>
                                <span className="techniqueName">{technique.name}</span>
                                <span className="techniqueCount">{technique.count}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
              
              {/* Threat Origin Map */}
              <div className="dashboardCard">
                <div className="cardHeader">
                  <h2>Top Threat Countries</h2>
                  <div className="cardActions">
                    <button className="cardAction">View Map</button>
                  </div>
                </div>
                <div className="cardContent">
                  <div className="threatCountries">
                    {threatCountries.map((country, i) => (
                      <div className="countryItem" key={i}>
                        <div className="countryFlag">{country.code}</div>
                        <div className="countryName">{country.name}</div>
                        <div className="countryBar">
                          <div className="countryBarFill" style={{ width: getBarHeight(country.count, 1500) }}></div>
                        </div>
                        <div className="countryCount">{country.count}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              
              {/* Threat Vectors */}
              <div className="dashboardCard">
                <div className="cardHeader">
                  <h2>Threat Vectors</h2>
                  <div className="cardActions">
                    <button className="cardAction">Details</button>
                  </div>
                </div>
                <div className="cardContent">
                  <div className="threatVectors">
                    {mockData.threatVectors.map((vector, i) => (
                      <div className="vectorItem" key={i}>
                        <div className="vectorLabel">
                          <span className="vectorDot"></span>
                          {vector.type}
                        </div>
                        <div className="vectorValue">{vector.count}</div>
                        <div className="vectorBar" style={{ width: getBarHeight(vector.count, 50) }}></div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
        
        {/* Threats Tab */}
        {activeTab === 'threats' && (
          <div className="dashboardContent">
            <div className="contentHeader">
              <h2>Active Threats</h2>
              <p>Monitoring and analysis of ongoing threats in your environment</p>
            </div>
            
            <div className="comingSoon">
              <p>This section is under development. The full implementation would include detailed threat tracking, impact assessment, and remediation tools.</p>
            </div>
          </div>
        )}
        
        {/* Anomalies Tab */}
        {activeTab === 'anomalies' && (
          <div className="dashboardContent">
            <div className="contentHeader">
              <h2>Anomaly Detection</h2>
              <p>Unusual patterns and behaviors detected by swarm intelligence algorithms</p>
            </div>
            
            <div className="comingSoon">
              <p>This section is under development. The full implementation would include behavior-based anomaly detection, baseline deviations, and predictive analytics.</p>
            </div>
          </div>
        )}
        
        {/* Alerts Tab */}
        {activeTab === 'alerts' && (
          <div className="dashboardContent">
            <div className="contentHeader">
              <h2>Alert Queue</h2>
              <p>Prioritized security alerts requiring attention or action</p>
            </div>
            
            <div className="alertFilters">
              <select className="filterSelect">
                <option>All Severities</option>
                <option>Critical Only</option>
                <option>High & Critical</option>
                <option>Medium & Above</option>
              </select>
              <select className="filterSelect">
                <option>All Sources</option>
                <option>Firewall</option>
                <option>Endpoint</option>
                <option>Cloud</option>
                <option>Authentication</option>
              </select>
              <select className="filterSelect">
                <option>Last 24 Hours</option>
                <option>Last 12 Hours</option>
                <option>Last Hour</option>
                <option>Real-time</option>
              </select>
              <button className="filterButton">Apply Filters</button>
            </div>
            
            <div className="alertTable fullWidth">
              <div className="tableHeader">
                <div className="tableCell">ID</div>
                <div className="tableCell">Source</div>
                <div className="tableCell">Severity</div>
                <div className="tableCell">Time</div>
                <div className="tableCell wide">Description</div>
                <div className="tableCell">Status</div>
                <div className="tableCell">Actions</div>
              </div>
              <div className="tableBody">
                {[...mockData.alerts, ...mockData.alerts].map((alert, index) => (
                  <div className={`tableRow ${alert.severity}`} key={index}>
                    <div className="tableCell">{alert.id}</div>
                    <div className="tableCell">{alert.source}</div>
                    <div className="tableCell">
                      <span className={`severityBadge ${alert.severity}`}>
                        {alert.severity}
                      </span>
                    </div>
                    <div className="tableCell">{alert.time}</div>
                    <div className="tableCell wide">{alert.description}</div>
                    <div className="tableCell">
                      <span className="statusBadge new">New</span>
                    </div>
                    <div className="tableCell">
                      <div className="actionButtons">
                        <button className="actionButton">Investigate</button>
                        <button className="actionButton">Dismiss</button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
        
        {/* Logs Tab */}
        {activeTab === 'logs' && (
          <div className="dashboardContent">
            <div className="contentHeader">
              <h2>Live Logs</h2>
              <p>Real-time log data from all monitored systems</p>
            </div>
            
            <div className="logControls">
              <div className="logSearch">
                <input type="text" placeholder="Search logs..." className="logSearchInput" />
              </div>
              <div className="logFilters">
                <select className="filterSelect">
                  <option>All Sources</option>
                  <option>Firewall</option>
                  <option>Endpoint</option>
                  <option>Authentication</option>
                  <option>Cloud Services</option>
                </select>
                <select className="filterSelect">
                  <option>All Types</option>
                  <option>AUTH</option>
                  <option>FIREWALL</option>
                  <option>ENDPOINT</option>
                  <option>API</option>
                  <option>CLOUD</option>
                </select>
                <select className="filterSelect">
                  <option>All Statuses</option>
                  <option>Normal</option>
                  <option>Warning</option>
                  <option>Blocked</option>
                  <option>Error</option>
                </select>
                <button className="filterButton">Stream Live</button>
              </div>
            </div>
            
            <div className="logStream">
              <div className="logHeader">
                <div className="logCell">ID</div>
                <div className="logCell">Time</div>
                <div className="logCell">Source</div>
                <div className="logCell">Type</div>
                <div className="logCell wide">Message</div>
                <div className="logCell">Status</div>
              </div>
              <div className="logBody">
                {mockData.liveData.map((log, index) => (
                  <div className={`logRow ${log.status}`} key={index}>
                    <div className="logCell">{log.id}</div>
                    <div className="logCell">{log.time}</div>
                    <div className="logCell">{log.source}</div>
                    <div className="logCell">{log.type}</div>
                    <div className="logCell wide">{log.message}</div>
                    <div className="logCell">
                      <span className={`statusIndicator ${log.status}`}></span>
                      {log.status}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}