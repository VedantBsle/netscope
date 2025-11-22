import React, { useState, useEffect } from "react";
import UploadForm from "./components/UploadForm";
import "./styles/styles.css";

function App() {
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setLoaded(true), 100);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="app-container">
      {/**/}
      {!loaded && (
        <div className="skeleton-overlay">
          <div className="skeleton-header"></div>
          <div className="skeleton-content"></div>
        </div>
      )}

      {/* Main Content */}
      {loaded && (
        <>
          <header className="site-header">
            <button
              className="logo-button"
              onClick={() => window.location.reload()}
              aria-label="Reload homepage"
            >
              <h1>PCAP-Viz</h1>
            </button>
            <p className="site-subtitle">Analyze network traffic in seconds</p>
          </header>

          <UploadForm />

          <footer className="site-footer">
            <p></p>
          </footer>
        </>
      )}
    </div>
  );
}

export default App;