import { useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import '../styles/globals.css';

export default function Home() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [taglineIndex, setTaglineIndex] = useState(0);
  const [analysisResults, setAnalysisResults] = useState(null);
  const [analysisError, setAnalysisError] = useState(null);
  
  const taglines = [
    "secure the future.",
    "fortify your systems.",
    "evolve with the data.",
    "shield your infrastructure.",
    "guard the digital horizon."
  ];

  useEffect(() => {
    const taglineInterval = setInterval(() => {
      setTaglineIndex((prevIndex) => (prevIndex + 1) % taglines.length);
    }, 1500);
    
    return () => clearInterval(taglineInterval);
  }, []);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      // Reset any previous results or errors
      setAnalysisResults(null);
      setAnalysisError(null);
      setSelectedFile(file);
    } else {
      alert('Please select a JSON file');
      e.target.value = null;
    }
  };

  const handleUpload = async () => {
    if (selectedFile) {
      setIsUploading(true);
      setAnalysisError(null);
      
      try {
        const fileContent = await readFileAsText(selectedFile);
        
        const jsonData = JSON.parse(fileContent);
        
        const response = await fetch('/api/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(jsonData),
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        
        const analysisData = await response.json();
        setAnalysisResults(analysisData);
      } catch (error) {
        console.error('Error during log analysis:', error);
        setAnalysisError(error.message || 'Failed to analyze logs. Please check the file format and try again.');
      } finally {
        setIsUploading(false);
      }
    }
  };
  
  // Helper function to read file as text
  const readFileAsText = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = (e) => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  };
  
  // Function to get status color class
  const getStatusColorClass = (status) => {
    switch(status?.toLowerCase()) {
      case 'safe':
        return 'safeColor';
      case 'suspicious':
        return 'warningColor';
      case 'threat':
        return 'dangerColor';
      default:
        return '';
    }
  };

  return (
    <div className="container">
      <Head>
        <title>aegiswarm | home</title>
        <meta name="description" content="security intelligence enhanced monitoring" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <header className="header">
        <div className="logo">
          aegis<span className="logoHighlight">warm</span>
        </div>
      </header>

      <main className="main">
        {/* Hero Section */}
        <div className="heroSection">
          <p className="taglineRotator">
            <span className="taglineFixed">swarm the threats.</span>
            <span className="taglineChanging">{taglines[taglineIndex]}</span>
          </p>
        </div>

        {/* Features Section */}
        <section className="featuresSection">
          <h2>features</h2>
          <div className="featuresGrid">
            <Link href="/features/log-collection" className="featureLink">
              <div className="featureCard">
                <div className="featureIcon">📋</div>
                <h3>log collection & aggregation</h3>
                <p><strong>ant colony optimization (ACO)</strong></p>
                <p>efficient pathfinding through massive log data</p>
              </div>
            </Link>
            <Link href="/features/threat-detection" className="featureLink">
              <div className="featureCard">
                <div className="featureIcon">⚡</div>
                <h3>real-time threat detection</h3>
                <p><strong>particle swarm optimization (PSO)</strong></p>
                <p>rapid convergence on potential threats</p>
              </div>
            </Link>
            <Link href="/features/anomaly-detection" className="featureLink">
              <div className="featureCard">
                <div className="featureIcon">🔺</div>
                <h3>anomaly detection</h3>
                <p><strong>artificial bee colony (ABC)</strong></p>
                <p>discover patterns that don't belong</p>
              </div>
            </Link>
            <Link href="/features/event-correlation" className="featureLink">
              <div className="featureCard">
                <div className="featureIcon">🔗</div>
                <h3>event correlation</h3>
                <p><strong>firefly algorithm</strong></p>
                <p>illuminate connections between security events</p>
              </div>
            </Link>
            <Link href="/features/alert-prioritization" className="featureLink">
              <div className="featureCard">
                <div className="featureIcon">📊</div>
                <h3>alert prioritization</h3>
                <p><strong>fish school search (FSS)</strong></p>
                <p>swim through noise to find what matters</p>
              </div>
            </Link>
            <Link href="/features/visualization" className="featureLink">
              <div className="featureCard">
                <div className="featureIcon">📈</div>
                <h3>visualization & dashboard</h3>
                <p><strong>grey wolf optimizer (GWO)</strong></p>
                <p>hunt for insights with pack intelligence</p>
              </div>
            </Link>
          </div>
        </section>

        {/* How It Works Section */}
        <section className="howItWorksSection">
          <h2>how it works</h2>
          <div className="stepsContainer">
            <div className="step">
              <div className="stepNumber">1</div>
              <p>upload your log file (JSON)</p>
            </div>
            <div className="stepArrow">→</div>
            <div className="step">
              <div className="stepNumber">2</div>
              <p>backend runs 6 swarm algorithms for detection</p>
            </div>
            <div className="stepArrow">→</div>
            <div className="step">
              <div className="stepNumber">3</div>
              <p>output shows threats, anomalies, correlations, and priority levels</p>
            </div>
            <div className="stepArrow">→</div>
            <div className="step">
              <div className="stepNumber">4</div>
              <p>dashboard visualizes everything</p>
            </div>
          </div>
        </section>

        {/* Upload Logs / Demo Section */}
        <section className="uploadSection">
          <h2>try it now</h2>
          <div className="uploadContainer">
            <div className="uploadBox">
              <input 
                type="file" 
                id="logFile" 
                onChange={handleFileChange} 
                accept=".json" 
                className="fileInput" 
              />
              <label htmlFor="logFile" className="fileInputLabel">
                {selectedFile ? selectedFile.name : "select a json log file"}
              </label>
              <button 
                onClick={handleUpload} 
                className="uploadButton" 
                disabled={!selectedFile || isUploading}
              >
                {isUploading ? "uploading..." : "analyze logs"}
              </button>
            </div>
            <div className="orDivider">or</div>
            <Link href="/dashboard" legacyBehavior>
              <a>
                <button className="demoButton">explore full dashboard</button>
              </a>
            </Link>
          </div>
          
          {/* Analysis Results */}
          {analysisResults && (
            <div className="analysisResults">
              <h3>Analysis Results</h3>
              <div className="resultsCard">
                <div className="resultHeader">
                  <div className="resultTitle">Overall Status:</div>
                  <div className={`resultValue ${getStatusColorClass(analysisResults.overall_status)}`}>
                    {analysisResults.overall_status}
                  </div>
                </div>
                
                <div className="threatScoreContainer">
                  <div className="resultTitle">Threat Score:</div>
                  <div className="threatScore">
                    <div className="threatScoreBar" style={{ width: `${analysisResults.threat_score * 100}%` }}></div>
                    <div className="threatScoreValue">{analysisResults.threat_score.toFixed(2)}</div>
                  </div>
                </div>
                
                <div className="algorithmScores">
                  <h4>Detection by Algorithm</h4>
                  <div className="algorithmGrid">
                    <div className="algorithmItem">
                      <div className="algorithmName">ACO</div>
                      <div className="algorithmScore" style={{height: `${analysisResults.detection_summary.aco * 100}%`}}></div>
                      <div className="algorithmValue">{analysisResults.detection_summary.aco.toFixed(2)}</div>
                    </div>
                    <div className="algorithmItem">
                      <div className="algorithmName">PSO</div>
                      <div className="algorithmScore" style={{height: `${analysisResults.detection_summary.pso * 100}%`}}></div>
                      <div className="algorithmValue">{analysisResults.detection_summary.pso.toFixed(2)}</div>
                    </div>
                    <div className="algorithmItem">
                      <div className="algorithmName">ABC</div>
                      <div className="algorithmScore" style={{height: `${analysisResults.detection_summary.abc * 100}%`}}></div>
                      <div className="algorithmValue">{analysisResults.detection_summary.abc.toFixed(2)}</div>
                    </div>
                    <div className="algorithmItem">
                      <div className="algorithmName">Firefly</div>
                      <div className="algorithmScore" style={{height: `${analysisResults.detection_summary.firefly * 100}%`}}></div>
                      <div className="algorithmValue">{analysisResults.detection_summary.firefly.toFixed(2)}</div>
                    </div>
                    <div className="algorithmItem">
                      <div className="algorithmName">FSS</div>
                      <div className="algorithmScore" style={{height: `${analysisResults.detection_summary.fss * 100}%`}}></div>
                      <div className="algorithmValue">{analysisResults.detection_summary.fss.toFixed(2)}</div>
                    </div>
                    <div className="algorithmItem">
                      <div className="algorithmName">GWO</div>
                      <div className="algorithmScore" style={{height: `${analysisResults.detection_summary.gwo * 100}%`}}></div>
                      <div className="algorithmValue">{analysisResults.detection_summary.gwo.toFixed(2)}</div>
                    </div>
                  </div>
                </div>
                
                <div className="resultActions">
                  <Link href="/dashboard" legacyBehavior>
                    <a>
                      <button className="viewDetailsButton">View Full Details</button>
                    </a>
                  </Link>
                </div>
              </div>
            </div>
          )}
          
          {analysisError && (
            <div className="analysisError">
              <h3>Analysis Error</h3>
              <p>{analysisError}</p>
            </div>
          )}
        </section>

        {/* Mini Dashboard Preview */}
        <section className="previewSection">
          <h2>visualization preview</h2>
          <div className="dashboardPreview">
            <div className="chartPreview pieChart">
              <div className="chartTitle">threat assessment</div>
              <div className="chartPlaceholder">
                <div className="pieChartVisual">
                  {/* Using conic-gradient in CSS instead of segments */}
                </div>
                <div className="chartLegend">
                  <div className="legendItem">
                    <span className="legendColor safe"></span>
                    <span>safe (72%)</span>
                  </div>
                  <div className="legendItem">
                    <span className="legendColor warning"></span>
                    <span>suspicious (18%)</span>
                  </div>
                  <div className="legendItem">
                    <span className="legendColor danger"></span>
                    <span>threat (10%)</span>
                  </div>
                </div>
              </div>
            </div>
            <div className="chartPreview barChart">
              <div className="chartTitle">anomaly scores</div>
                <div className="chartPlaceholder">
                  <div className="barContainer">
                    <div className="barGroup">
                      <div className="bar low" style={{height: "30%"}}></div>
                      <div className="barLabel">
                        <span className="score">0.23</span>
                        <span className="severity low">low</span>
                      </div>
                    </div>
                    <div className="barGroup">
                      <div className="bar medium" style={{height: "50%"}}></div>
                      <div className="barLabel">
                        <span className="score">0.47</span>
                        <span className="severity medium">medium</span>
                      </div>
                    </div>
                    <div className="barGroup">
                      <div className="bar high" style={{height: "70%"}}></div>
                      <div className="barLabel">
                        <span className="score">0.78</span>
                        <span className="severity high">high</span>
                      </div>
                    </div>
                    <div className="barGroup">
                      <div className="bar high" style={{height: "90%"}}></div>
                      <div className="barLabel">
                        <span className="score">0.92</span>
                        <span className="severity high">critical</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            <div className="chartPreview tablePreview">
              <div className="chartTitle">recent logs</div>
              <div className="chartPlaceholder">
                <table className="previewTable">
                  <thead>
                    <tr>
                      <th>time</th>
                      <th>source</th>
                      <th>severity</th>
                      <th>anomaly score</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td>09:45:22</td>
                      <td>192.168.1.5</td>
                      <td className="severity low">low</td>
                      <td>0.23</td>
                    </tr>
                    <tr>
                      <td>09:42:17</td>
                      <td>192.168.1.105</td>
                      <td className="severity high">high</td>
                      <td>0.78</td>
                    </tr>
                    <tr>
                      <td>09:40:03</td>
                      <td>192.168.1.78</td>
                      <td className="severity medium">medium</td>
                      <td>0.47</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <div className="footerContent">
          <div className="footerSection">
            <p>aegiswarm © {new Date().getFullYear()} | by adithya</p>
          </div>
          <div className="footerSection">
            <a href="https://github.com/adithya16pillai/Aegiswarm" target="_blank" rel="noopener noreferrer" className="footerLink">
              <svg className="githubIcon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
                <path fill="currentColor" d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.385-1.335-1.755-1.335-1.755-1.087-.745.084-.73.084-.73 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.807 1.305 3.492.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12"/>
              </svg>
            </a>
          </div>
          <div className="footerSection">
            <p>created by adithya rajesh pillai</p>
          </div>
        </div>
      </footer>
    </div>
  );
}