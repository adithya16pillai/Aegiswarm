import { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import '../../styles/globals.css';
import '../../styles/feature-animations.css';

export default function AlertPrioritization() {
  return (
    <div className="container">
      <Head>
        <title>aegiswarm | alert prioritization</title>
        <meta name="description" content="Intelligent alert prioritization with Fish School Search" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <header className="header">
        <Link href="/">
          <div className="logo">
            aegis<span className="logoHighlight">warm</span>
          </div>
        </Link>
        <nav className="navLinks">
          <Link href="/" className="navLink">home</Link>
        </nav>
      </header>

      <main className="main featurePage">
        <div className="featureHero">
          <div className="featureIcon large">📊</div>
          <h1 className="featureTitle">alert prioritization</h1>
          <div className="featureTagline">powered by <strong>fish school search (FSS)</strong></div>
        </div>

        <div className="featureContent">
          <section className="featureSection">
            <h2>how it works</h2>
            <p>The Fish School Search algorithm mimics how fish swim together to find food efficiently. In our security context:</p>
            
            <div className="featurePoints">
              <div className="featurePoint">
                <h3>collective weightings</h3>
                <p>Like fish swimming toward food, our agents collectively evaluate alerts and "swim" toward those with the highest security significance.</p>
              </div>
              
              <div className="featurePoint">
                <h3>feeding & weight adjustment</h3>
                <p>Alerts confirmed as significant gain "weight" in the system, making similar future alerts more likely to be prioritized.</p>
              </div>
              
              <div className="featurePoint">
                <h3>individual & collective movement</h3>
                <p>Each agent explores independently but is influenced by the collective findings of the group, ensuring both thorough coverage and convergence on true threats.</p>
              </div>
            </div>
          </section>

          <section className="featureSection">
            <h2>key benefits</h2>
            <ul className="benefitsList">
              <li>Reduce alert fatigue by focusing on what truly matters</li>
              <li>Dynamic priority scoring that adapts to your environment</li>
              <li>Multi-factor evaluation considering context, impact, and likelihood</li>
              <li>Clear visualization of priority levels for quick decision-making</li>
              <li>Integration of human feedback to continuously improve prioritization</li>
            </ul>
          </section>

          <div className="featureDemo">
            <h2>see it in action</h2>
            <div className="demoVisual">
              <div className="demoPlaceholder">
                <div className="fss-animation">
                  <div className="fish f1"></div>
                  <div className="fish f2"></div>
                  <div className="fish f3"></div>
                  <div className="fish f4"></div>
                  <div className="fish f5"></div>
                  <div className="alert a1"></div>
                  <div className="alert a2"></div>
                  <div className="alert a3"></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="backToHome">
          <Link href="/">
            <button className="secondaryButton">← back to home</button>
          </Link>
        </div>
      </main>

      <footer className="footer">
        <div className="footerContent">
          <div className="footerSection">
            <p>aegiswarm © {new Date().getFullYear()} | powered by swarm intelligence</p>
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