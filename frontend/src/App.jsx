import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Upload,
  Mail,
  User,
  Link,
  Brain,
  LockKeyhole,
} from "lucide-react";

function App() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [scoreWidth, setScoreWidth] = useState(0);
  
  useEffect(() => {
  if (!result) {
    setScoreWidth(0);
    return;
  }

  setScoreWidth(0);

  const timer = setTimeout(() => {
    setScoreWidth(
      result.threat_assessment?.score ?? 0
    );
  }, 100);

  return () => clearTimeout(timer);
}, [result]);
  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];

    setError("");
    setResult(null);

    if (!selectedFile) {
      setFile(null);
      return;
    }

    if (!selectedFile.name.toLowerCase().endsWith(".eml")) {
      setError("Please select a valid .eml file.");
      setFile(null);
      return;
    }

    setFile(selectedFile);
  };

  const analyzeEmail = async () => {
    if (!file) {
      setError("Please select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(
        "http://127.0.0.1:8000/api/email/analyze",
        {
          method: "POST",
          body: formData,
        }
      );

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const data = await response.json();

      if (!data.success) {
        throw new Error("Email analysis failed.");
      }

      setResult(data.analysis);
    } catch (err) {
      setError(
        err.message ||
          "Unable to connect to the backend. Make sure FastAPI is running."
      );
    } finally {
      setLoading(false);
    }
  };

  const getRiskClass = (riskLevel) => {
    if (riskLevel === "CRITICAL") return "critical";
    if (riskLevel === "HIGH") return "high";
    if (riskLevel === "MEDIUM") return "medium";
    return "low";
  };

  return (
    <div className="app">
      {/* HEADER */}
      <header className="header">
        <div className="brand">
          <div className="brand-icon">
            <ShieldAlert size={25} />
          </div>

          <div>
            <h1>Email Threat Detection</h1>
            <p>AI-Powered Email Forensics & Threat Intelligence</p>
          </div>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          System Online
        </div>
      </header>

      <main className="container">
        {/* UPLOAD */}
        <section className="upload-card">
          <div className="upload-icon">
            <Upload size={30} />
          </div>

          <h2>Analyze an Email</h2>

          <p>
            Upload an <strong>.eml</strong> file to perform forensic analysis,
            threat detection, reputation checks and AI investigation.
          </p>

          <label className="file-input">
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={handleFileChange}
            />

            <Upload size={18} />

            <span>
              {file ? file.name : "Choose an .eml file"}
            </span>
          </label>

          {file && (
            <div className="selected-file">
              <Mail size={16} />
              <span>{file.name}</span>
            </div>
          )}

          <button
            className="analyze-button"
            onClick={analyzeEmail}
            disabled={!file || loading}
          >
            {loading ? "Analyzing Email..." : "Analyze Email"}
          </button>

          {error && (
            <div className="error">
              <AlertTriangle size={18} />
              {error}
            </div>
          )}
        </section>

        {/* RESULTS */}
        {result && (
          <div className="dashboard">
            {/* THREAT OVERVIEW */}
            <section className="threat-card">
              <div className="section-title">
                <ShieldAlert size={21} />
                <span>Threat Overview</span>
              </div>

              <div className="threat-grid">
                <div
                  className={`risk-box ${getRiskClass(
                    result.threat_assessment.risk_level
                  )}`}
                >
                  <span className="label">RISK LEVEL</span>

                  <strong>
                    {result.threat_assessment.risk_level}
                  </strong>

                  <small>
                    Confidence:{" "}
                    {Math.round(
                      result.threat_assessment.confidence * 100
                    )}
                    %
                  </small>
                </div>

                <div className="score-box">
  <span className="label">THREAT SCORE</span>

  <div className="score-display">
    <strong>
      {result.threat_assessment.score}
    </strong>
    <span>/100</span>
  </div>

  <div className="score-bar">
    <div
      style={{
  width: `${scoreWidth}%`,
}}
    ></div>
  </div>

  <div className="score-scale">
    <span>0</span>
    <span>25</span>
    <span>50</span>
    <span>75</span>
    <span>100</span>
  </div>
</div>

                <div className="verdict-box">
                  <span className="label">VERDICT</span>

                  <strong>
                    {result.threat_assessment.verdict}
                  </strong>

                  <small>Deterministic analysis</small>
                </div>
              </div>

              <div className="classification-grid">
                <div className="classification">
                  <span>Attack Type</span>
                  <strong>
                    {result.attack_type_assessment.attack_type}
                  </strong>
                </div>

                <div className="classification">
                  <span>Phishing</span>
                  <strong>
                    {result.phishing_assessment.classification}
                  </strong>
                </div>

                <div className="classification">
                  <span>Social Engineering</span>
                  <strong
                    className={
                      result.social_engineering_assessment
                        .social_engineering
                        ? "danger-text"
                        : "safe-text"
                    }
                  >
                    {result.social_engineering_assessment
                      .social_engineering
                      ? "YES"
                      : "NO"}
                  </strong>
                </div>
              </div>
            </section>

            {/* EMAIL DETAILS */}
            <section className="card">
              <div className="section-title">
                <Mail size={21} />
                <span>Email Details</span>
              </div>

              <div className="details-grid">
                <div>
                  <span>Sender</span>
                  <strong>{result.headers.from}</strong>
                </div>

                <div>
                  <span>Recipient</span>
                  <strong>{result.headers.to}</strong>
                </div>

                <div>
                  <span>Reply-To</span>
                  <strong className="danger-text">
                    {result.headers.reply_to || "None"}
                  </strong>
                </div>

                <div>
                  <span>Subject</span>
                  <strong>{result.headers.subject}</strong>
                </div>
              </div>
            </section>

            {/* AUTHENTICATION */}
            <section className="card">
              <div className="section-title">
                <LockKeyhole size={21} />
                <span>Email Authentication</span>
              </div>

              <div className="authentication-grid">
                {[
                  ["SPF", result.authentication.spf],
                  ["DKIM", result.authentication.dkim],
                  ["DMARC", result.authentication.dmarc],
                ].map(([name, value]) => (
                  <div
                    className={`auth-box ${
                      value === "fail" ? "auth-fail" : "auth-pass"
                    }`}
                    key={name}
                  >
                    <span>{name}</span>

                    <strong>
                      {value === "fail" ? "✕ FAIL" : "✓ PASS"}
                    </strong>
                  </div>
                ))}
              </div>
            </section>

            {/* AI INVESTIGATION */}
            <section className="ai-card">
              <div className="section-title">
                <Brain size={22} />
                <span>AI Investigation</span>

                {result.llm_investigation.enabled && (
                  <span className="ai-badge">
                    Gemini AI
                  </span>
                )}
              </div>

              {result.llm_investigation.enabled &&
              result.llm_investigation.analysis ? (
                <>
                  <div className="ai-summary">
                    <h3>Executive Assessment</h3>

                    <p>
                      {
                        result.llm_investigation.analysis
                          .executive_assessment
                      }
                    </p>
                  </div>

                  <div className="ai-columns">
                    <div>
                      <h3>Key Evidence</h3>

                      <ul>
                        {result.llm_investigation.analysis.key_evidence?.map(
                          (item, index) => (
                            <li key={index}>{item}</li>
                          )
                        )}
                      </ul>
                    </div>

                    <div>
                      <h3>Social Engineering</h3>

                      <div className="techniques">
                        {result.llm_investigation.analysis.social_engineering_techniques?.map(
                          (technique) => (
                            <span key={technique}>
                              {technique}
                            </span>
                          )
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="recommendations">
                    <h3>Recommended Actions</h3>

                    <ul>
                      {result.llm_investigation.analysis.recommended_actions?.map(
                        (action, index) => (
                          <li key={index}>{action}</li>
                        )
                      )}
                    </ul>
                  </div>
                </>
              ) : (
                <p className="ai-unavailable">
                  AI investigation is currently unavailable.
                </p>
              )}
            </section>

            {/* URL INTELLIGENCE */}
            <section className="card">
              <div className="section-title">
                <Link size={21} />
                <span>URL Intelligence</span>
              </div>

              {result.urls.length === 0 ? (
                <p className="muted">No URLs detected.</p>
              ) : (
                result.urls.map((url) => (
                  <div className="url-row" key={url.url}>
                    <div>
                      <strong>{url.url}</strong>
                      <span>{url.domain}</span>
                    </div>

                    <span className="safe-badge">
                      No Threat Detected
                    </span>
                  </div>
                ))
              )}
            </section>

            {/* ORIGIN */}
            <section className="card">
              <div className="section-title">
                <User size={21} />
                <span>Origin Analysis</span>
              </div>

              <div className="origin-box">
                <div>
                  <span>Earliest Reliable IP</span>

                  <strong>
                    {result.origin_analysis
                      .earliest_reliable_ip ||
                      "No reliable public origin IP"}
                  </strong>
                </div>

                <div>
                  <span>Confidence</span>

                  <strong>
                    {Math.round(
                      result.origin_analysis.confidence * 100
                    )}
                    %
                  </strong>
                </div>

                <p>{result.origin_analysis.reason}</p>
              </div>
            </section>

            {/* INDICATORS */}
            <section className="card">
              <div className="section-title">
                <AlertTriangle size={21} />
                <span>Threat Indicators</span>

                <span className="indicator-count">
                  {result.indicators.length}
                </span>
              </div>

              <div className="indicator-list">
                {result.indicators.map((indicator, index) => (
                  <div
                    className="indicator"
                    key={`${indicator.type}-${index}`}
                  >
                    <div>
                      <strong>{indicator.type}</strong>
                      <p>{indicator.description}</p>
                    </div>

                    <span
                      className={`severity ${indicator.severity.toLowerCase()}`}
                    >
                      {indicator.severity}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;