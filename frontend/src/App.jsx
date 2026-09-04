import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Upload,
  Download,
  Mail,
  User,
  Link as LinkIcon,
  Brain,
  LockKeyhole,
  Globe2,
  Paperclip,
  Fingerprint,
  ChevronRight,
} from "lucide-react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

import markerIcon from "leaflet/dist/images/marker-icon.png";
import markerIconRetina from "leaflet/dist/images/marker-icon-2x.png";
import markerShadow from "leaflet/dist/images/marker-shadow.png";
import { useEffect, useState } from "react";
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  Polyline,
} from "react-leaflet";

const API_BASE = "";

const defaultMarkerIcon = L.icon({
  iconUrl: markerIcon,
  iconRetinaUrl: markerIconRetina,
  shadowUrl: markerShadow,

  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

L.Marker.prototype.options.icon = defaultMarkerIcon;

function OriginMap({ origin, destination }) {
  if (
    !origin?.latitude ||
    !origin?.longitude
  ) {
    return (
      <div className="origin-map-empty">
        <Globe2 size={24} />
        <span>
          Geographic origin unavailable for this email.
        </span>
      </div>
    );
  }

  const originPosition = [
    origin.latitude,
    origin.longitude,
  ];

  const destinationPosition =
    destination?.latitude &&
    destination?.longitude
      ? [
          destination.latitude,
          destination.longitude,
        ]
      : null;

  const center = destinationPosition
    ? [
        (originPosition[0] + destinationPosition[0]) / 2,
        (originPosition[1] + destinationPosition[1]) / 2,
      ]
    : originPosition;

  return (
    <div className="origin-map">
      <MapContainer
        center={center}
        zoom={destinationPosition ? 3 : 5}
        scrollWheelZoom={false}
        style={{ height: "360px", width: "100%" }}
      >
        <TileLayer
          attribution='&copy; OpenStreetMap contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        <Marker position={originPosition}>
          <Popup>
            <strong>Suspected Origin</strong>
            <br />
            IP: {origin.ip}
            <br />
            {origin.city || "Unknown city"}
            {origin.country
              ? `, ${origin.country}`
              : ""}
            <br />
            {origin.organization || "Unknown network"}
          </Popup>
        </Marker>

        {destinationPosition && (
          <>
            <Marker position={destinationPosition}>
              <Popup>
                <strong>Recipient</strong>
                <br />
                {destination.country || "Unknown location"}
              </Popup>
            </Marker>

            <Polyline
              positions={[
                originPosition,
                destinationPosition,
              ]}
            />
          </>
        )}
      </MapContainer>
    </div>
  );
}

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
      setScoreWidth(result.threat_assessment?.score ?? 0);
    }, 100);

    return () => clearTimeout(timer);
  }, [result]);

  const handleFileChange = (event) => {
    const selectedFile = event.target.files?.[0];
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

      const response = await fetch(`${API_BASE}/api/email/analyze`, {
        method: "POST",
        body: formData,
      });

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

  const downloadReport = async () => {
    if (!result) return;

    try {
      setError("");
      const response = await fetch(`${API_BASE}/api/email/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(result),
      });

      if (!response.ok) {
        throw new Error(`Report generation failed (${response.status})`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${result.filename?.replace(/\.eml$/i, "") || "email"}_forensic_report.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message || "Unable to generate the forensic report.");
    }
  };

  const getRiskClass = (riskLevel) => {
    if (riskLevel === "CRITICAL") return "critical";
    if (riskLevel === "HIGH") return "high";
    if (riskLevel === "MEDIUM") return "medium";
    return "low";
  };

  const getAuthState = (value) => {
    const normalized = String(value || "unknown").toLowerCase();
    if (normalized === "pass") return { className: "auth-pass", icon: "✓", label: "PASS" };
    if (["fail", "softfail", "permerror", "temperror"].includes(normalized)) {
      return { className: "auth-fail", icon: "✕", label: "FAIL" };
    }
    return { className: "auth-unknown", icon: "?", label: "UNKNOWN" };
  };
  
    const groupedIndicators = Object.values(
    (result?.indicators || []).reduce((groups, indicator) => {
      const type = indicator.type || "UNKNOWN";

      if (!groups[type]) {
        groups[type] = {
          ...indicator,
          count: 0,
        };
      }

      groups[type].count += 1;

      return groups;
    }, {})
  );

  const reputationCount =
    (result?.ip_reputation?.length || 0) +
    (result?.domain_reputation?.length || 0) +
    (result?.url_reputation?.length || 0);

    const originIp =
    result?.origin_analysis?.earliest_reliable_ip;

  const originIntel =
    result?.ip_intelligence?.find(
      (item) => item.ip === originIp
    );

  const originGeo =
    originIntel?.enrichment?.available
      ? originIntel.enrichment
      : null;

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <div className="brand-icon"><ShieldAlert size={25} /></div>
          <div>
            <h1>Email Threat Detection</h1>
            <p>AI-Powered Email Forensics & Threat Intelligence</p>
          </div>
        </div>
        <div className="status"><span className="status-dot" /> System Online</div>
      </header>

      <main className="container">
        <section className="upload-card">
          <div className="upload-icon"><Upload size={30} /></div>
          <div className="eyebrow">FORENSIC ANALYSIS PLATFORM</div>
          <h2>Analyze an Email</h2>
          <p>
            Upload an <strong>.eml</strong> file for header forensics, URL and attachment
            analysis, threat intelligence, origin analysis and Gemini AI investigation.
          </p>

          <label className="file-input">
            <input type="file" accept=".eml,message/rfc822" onChange={handleFileChange} />
            <Upload size={18} />
            <span>{file ? file.name : "Choose an .eml file"}</span>
          </label>

          {file && (
            <div className="selected-file">
              <Mail size={16} />
              <span>{file.name}</span>
              <span className="file-size">{(file.size / 1024).toFixed(1)} KB</span>
            </div>
          )}

          <button className="analyze-button" onClick={analyzeEmail} disabled={!file || loading}>
            {loading ? "Analyzing Email..." : "Analyze Email"}
            {!loading && <ChevronRight size={18} />}
          </button>

          {error && (
            <div className="error"><AlertTriangle size={18} />{error}</div>
          )}
        </section>

        {result && (
          <div className="dashboard">
            <section className="dashboard-intro">
              <div>
                <div className="eyebrow">ANALYSIS COMPLETE</div>
                <h2>Forensic Investigation</h2>
                <p>{result.filename || "Analyzed email"}</p>
              </div>
              <div className="analysis-status"><ShieldCheck size={17} /> Evidence collected</div>
            </section>

            <section className="threat-card">
              <div className="section-title"><ShieldAlert size={21} /><span>Threat Overview</span></div>

              <div className="threat-grid">
                <div className={`risk-box ${getRiskClass(result.threat_assessment?.risk_level)}`}>
                  <span className="label">RISK LEVEL</span>
                  <strong>{result.threat_assessment?.risk_level || "UNKNOWN"}</strong>
                  <small>Confidence: {Math.round((result.threat_assessment?.confidence || 0) * 100)}%</small>
                </div>

                <div className="score-box">
                  <span className="label">THREAT SCORE</span>
                  <div className="score-display">
                    <strong>{result.threat_assessment?.score ?? 0}</strong><span>/100</span>
                  </div>
                  <div className="score-bar"><div style={{ width: `${scoreWidth}%` }} /></div>
                  <div className="score-scale"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
                </div>

                <div className="verdict-box">
                  <span className="label">VERDICT</span>
                  <strong>{result.threat_assessment?.verdict || "UNKNOWN"}</strong>
                  <small>Deterministic analysis</small>
                </div>
              </div>

              <div className="classification-grid">
                <div className="classification"><span>Attack Type</span><strong>{result.attack_type_assessment?.attack_type || "—"}</strong></div>
                <div className="classification"><span>Phishing</span><strong>{result.phishing_assessment?.classification || "—"}</strong></div>
                <div className="classification"><span>Social Engineering</span><strong className={result.social_engineering_assessment?.social_engineering ? "danger-text" : "safe-text"}>{result.social_engineering_assessment?.social_engineering ? "YES" : "NO"}</strong></div>
              </div>
            </section>

            <section className="snapshot-grid">
              <div className="snapshot-card"><div className="snapshot-icon"><LinkIcon size={18} /></div><span>URLs</span><strong>{result.urls?.length || 0}</strong><small>Analyzed</small></div>
              <div className="snapshot-card"><div className="snapshot-icon"><Paperclip size={18} /></div><span>Attachments</span><strong>{result.attachments?.length || 0}</strong><small>Detected</small></div>
              <div className="snapshot-card"><div className="snapshot-icon"><AlertTriangle size={18} /></div><span>Indicators</span><strong>{result.indicators?.length || 0}</strong><small>Threat signals</small></div>
              <div className="snapshot-card"><div className="snapshot-icon"><Globe2 size={18} /></div><span>Reputation Checks</span><strong>{reputationCount}</strong><small>Provider results</small></div>
            </section>

            <section className="card">
              <div className="section-title"><Mail size={21} /><span>Email Details</span></div>
              <div className="details-grid">
                <div><span>Sender</span><strong>{result.headers?.from || "—"}</strong></div>
                <div><span>Recipient</span><strong>{result.headers?.to || "—"}</strong></div>
                <div><span>Reply-To</span><strong>{result.headers?.reply_to || "None"}</strong></div>
                <div><span>Subject</span><strong>{result.headers?.subject || "—"}</strong></div>
              </div>
            </section>

            <section className="card">
              <div className="section-title"><LockKeyhole size={21} /><span>Email Authentication</span><span className="section-note">SPF / DKIM / DMARC</span></div>
              <div className="authentication-grid">
                {["spf", "dkim", "dmarc"].map((name) => {
                  const state = getAuthState(result.authentication?.[name]);
                  return (
                    <div className={`auth-box ${state.className}`} key={name}>
                      <span>{name.toUpperCase()}</span>
                      <strong>{state.icon} {state.label}</strong>
                    </div>
                  );
                })}
              </div>
            </section>

            <section className="card">
              <div className="section-title"><Fingerprint size={21} /><span>Identity & Origin</span></div>
              <div className="origin-grid">
                <div className="origin-box">
                  <span>Earliest Reliable IP</span>
                  <strong>{result.origin_analysis?.earliest_reliable_ip || "No reliable public origin IP"}</strong>
                  <small>Confidence: {Math.round((result.origin_analysis?.confidence || 0) * 100)}%</small>
                </div>
                {originGeo && (
  <OriginMap
    origin={originGeo}
  />
)}
                <div className="origin-box">
                  <span>Sender Domain</span>
                  <strong>{result.domains?.sender_domain || "—"}</strong>
                  <small>Reply-To: {result.domains?.reply_to_domain || "—"}</small>
                </div>
              </div>
              {result.origin_analysis?.reason && <p className="origin-reason">{result.origin_analysis.reason}</p>}
            </section>

            <section className="ai-card">
              <div className="section-title"><Brain size={22} /><span>AI Investigation</span>{result.llm_investigation?.enabled && <span className="ai-badge">Gemini AI</span>}</div>
              {result.llm_investigation?.enabled && result.llm_investigation?.analysis ? (
                <>
                  <div className="ai-summary"><h3>Executive Assessment</h3><p>{result.llm_investigation.analysis.executive_assessment}</p></div>
                  <div className="ai-columns">
                    <div><h3>Key Evidence</h3><ul>{result.llm_investigation.analysis.key_evidence?.map((item, i) => <li key={i}>{item}</li>)}</ul></div>
                    <div><h3>Social Engineering</h3><div className="techniques">{result.llm_investigation.analysis.social_engineering_techniques?.map((technique) => <span key={technique}>{technique}</span>)}</div></div>
                  </div>
                  <div className="recommendations"><h3>Recommended Actions</h3><ul>{result.llm_investigation.analysis.recommended_actions?.map((action, i) => <li key={i}>{action}</li>)}</ul></div>
                </>
              ) : <p className="ai-unavailable">AI investigation is currently unavailable.</p>}
            </section>

            <section className="card">
              <div className="section-title"><LinkIcon size={21} /><span>URL Intelligence</span><span className="section-note">{result.urls?.length || 0} detected</span></div>
              {result.urls?.length ? result.urls.map((url, index) => (
                <div className="url-row" key={`${url.url}-${index}`}>
                  <div><strong>{url.url}</strong><span>{url.domain || "Unknown domain"}</span></div>
                  <span className="safe-badge">{url.threat_detected ? "Threat Detected" : "No Threat Detected"}</span>
                </div>
              )) : <p className="muted">No URLs detected.</p>}
            </section>

                        <section className="card">
              <div className="section-title">
                <AlertTriangle size={21} />
                <span>Threat Indicators</span>
                <span className="indicator-count">
                  {groupedIndicators.length}
                </span>
              </div>

              {groupedIndicators.length ? (
                <div className="indicator-list">
                  {groupedIndicators.map((indicator) => (
                    <div className="indicator" key={indicator.type}>
                      <div>
                        <strong>{indicator.type}</strong>

                        {indicator.count > 1 && (
                          <span className="indicator-occurrences">
                            {indicator.count} occurrences
                          </span>
                        )}

                        <p>{indicator.description}</p>
                      </div>

                      <span
                        className={`severity ${(indicator.severity || "low").toLowerCase()}`}
                      >
                        {indicator.severity || "LOW"}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <ShieldCheck size={20} />
                  No threat indicators detected.
                </div>
              )}
            </section>

            <section className="report-card">
              <div>
                <div className="eyebrow">FINAL EVIDENCE PACKAGE</div>
                <h2>Ready for forensic reporting?</h2>
                <p>Export the complete analysis, evidence, reputation results and AI investigation as a PDF.</p>
              </div>
              <button className="download-report-button" onClick={downloadReport}>
                <Download size={18} />
                Download Forensic Report
              </button>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
