import { useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import '../../styles/globals.css';
import '../../styles/feature-animations.css';

export default function EventCorrelation() {
  return (
    <div className="container">
      <Head>
        <title>aegiswarm | event correlation</title>
        <meta name="description" content="Advanced event correlation with Firefly Algorithm" />
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
          <div className="featureIcon large">🔗</div>
          <h1 className="featureTitle">event correlation</h1>
          <div className="featureTagline">powered by <strong>firefly algorithm</strong></div>
        </div>

        <div className="featureContent">
          <section className="featureSection">
            <h2>how it works</h2>
            <p>The Firefly Algorithm is inspired by the flashing behavior of fireflies, where their light patterns communicate and attract. In our security system:</p>
            
            <div className="featurePoints">
              <div className="featurePoint">
                <h3>attract & connect</h3>
                <p>Security events "attract" each other based on similarities and potential causal relationships, automatically forming clusters of related incidents.</p>
              </div>
              
              <div className="featurePoint">
                <h3>brightness as significance</h3>
                <p>More significant events emit "brighter signals," pulling in related events from across your network and creating a comprehensive attack narrative.</p>
              </div>
              
              <div className="featurePoint">
                <h3>distance weighting</h3>
                <p>Correlation strength is intelligently weighted based on temporal proximity, logical connection, and statistical likelihood of true relationship.</p>
              </div>
            </div>
          </section>

          <section className="featureSection">
            <h2>key benefits</h2>
            <ul className="benefitsList">
              <li>Automatically identify multi-stage attacks spanning different systems</li>
              <li>Reduce thousands of alerts into manageable, contextual incidents</li>
              <li>Visualize attack chains and progression patterns</li>
              <li>Uncover subtle relationships between seemingly unrelated events</li>
              <li>Prioritize response based on comprehensive attack context</li>
            </ul>
          </section>

          <div className="featureDemo">
            <h2>see it in action</h2>
            <div className="demoVisual">
              <div className="demoPlaceholder">
                <div className="firefly-animation">
                  <div className="firefly f1"></div>
                  <div className="firefly f2"></div>
                  <div className="firefly f3"></div>
                  <div className="firefly f4"></div>
                  <div className="firefly f5"></div>
                  <div className="connection c1"></div>
                  <div className="connection c2"></div>
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