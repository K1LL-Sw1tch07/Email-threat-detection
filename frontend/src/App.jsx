// Replace your current App.jsx with this version.
// Origin is now a single card containing Sender Domain, Earliest Reliable IP,
// and the complete Mail Relay Path.
//
// IMPORTANT: keep your existing index.css unchanged.

import { AlertTriangle, ShieldAlert, ShieldCheck, Upload, Download, Mail, Link as LinkIcon, Brain, LockKeyhole, Globe2, Paperclip, Fingerprint, ChevronRight } from "lucide-react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import markerIcon from "leaflet/dist/images/marker-icon.png";
import markerIconRetina from "leaflet/dist/images/marker-icon-2x.png";
import markerShadow from "leaflet/dist/images/marker-shadow.png";
import { useEffect, useState } from "react";
import { MapContainer, TileLayer, Marker, Popup, Polyline } from "react-leaflet";

const API_BASE = "";
const defaultMarkerIcon = L.icon({ iconUrl: markerIcon, iconRetinaUrl: markerIconRetina, shadowUrl: markerShadow, iconSize: [25,41], iconAnchor:[12,41], popupAnchor:[1,-34], shadowSize:[41,41] });
L.Marker.prototype.options.icon = defaultMarkerIcon;

function OriginMap({ origin, hops = [] }) {
  const allHops = (Array.isArray(hops) ? hops : []).filter(h => h?.ip).sort((a,b) => Number(a.hop||0)-Number(b.hop||0));
  const points = allHops.map(h => {
    const g=h.geo||{}, e=h.enrichment||{}, gl=h.geolocation||{};
    return {...h, geo:{...g,
      latitude:g.latitude ?? gl.latitude ?? e.latitude ?? null,
      longitude:g.longitude ?? gl.longitude ?? e.longitude ?? null,
      city:g.city ?? gl.city ?? e.city ?? null,
      country:g.country ?? gl.country ?? e.country ?? null,
      organization:g.organization ?? gl.organization ?? e.organization ?? null,
      provider:g.provider ?? gl.provider ?? e.provider ?? null}};
  });
  const mapped = points.filter(p => Number.isFinite(Number(p.geo.latitude)) && Number.isFinite(Number(p.geo.longitude)));
  const fallback = origin && Number.isFinite(Number(origin.latitude)) && Number.isFinite(Number(origin.longitude))
    ? [{hop:1,ip:origin.ip,geo:origin}] : [];
  const mapPoints = mapped.length ? mapped : fallback;
  if (!mapPoints.length) return <div className="origin-map-empty"><Globe2 size={24}/><span>Geographic origin unavailable for this email.</span></div>;

  const positions=mapPoints.map(p=>[Number(p.geo.latitude),Number(p.geo.longitude)]);
  const center=positions.reduce((a,p)=>[a[0]+p[0]/positions.length,a[1]+p[1]/positions.length],[0,0]);

  return <div className="origin-map">
    <div className="relay-map-header"><div><strong>Mail Relay Path</strong><span>{allHops.length || mapPoints.length} relay hop{(allHops.length || mapPoints.length)!==1?"s":""} detected</span></div></div>
    <MapContainer center={center} zoom={2} scrollWheelZoom={false} style={{height:"360px",width:"100%"}}>
      <TileLayer attribution="&copy; OpenStreetMap contributors" url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"/>
      {positions.length>1 && <Polyline positions={positions} pathOptions={{weight:4,opacity:.85}}/>}
      {mapPoints.map((p,i)=><Marker key={`${p.ip}-${p.hop}-${i}`} position={[Number(p.geo.latitude),Number(p.geo.longitude)]}>
        <Popup><strong>{i===0?"Earliest Reliable Origin":`Relay Hop ${p.hop}`}</strong><br/>IP: {p.ip}<br/>{p.geo.city||"Unknown city"}{p.geo.country?`, ${p.geo.country}`:""}<br/>{p.geo.organization||p.geo.provider||"Unknown network"}<br/><small>Hop {p.hop}</small></Popup>
      </Marker>)}
    </MapContainer>
    <div className="relay-hop-list">
      {allHops.map((p,i)=><div className="relay-hop" key={`list-${p.ip}-${p.hop}-${i}`}>
        <div className="relay-hop-number">{p.hop}</div>
        <div className="relay-hop-info"><strong>{i===0?"Earliest Origin":`Relay Hop ${p.hop}`}</strong><span>{p.ip}</span><small>{p.geo?.organization||p.geo?.provider||"Geolocation unavailable"}</small></div>
        {i<allHops.length-1&&<ChevronRight size={16} className="relay-hop-arrow"/>}
      </div>)}
    </div>
  </div>;
}

function App() {
  const [file,setFile]=useState(null),[loading,setLoading]=useState(false),[result,setResult]=useState(null),[error,setError]=useState(""),[scoreWidth,setScoreWidth]=useState(0);
  useEffect(()=>{if(!result){setScoreWidth(0);return} const t=setTimeout(()=>setScoreWidth(result.threat_assessment?.score??0),100);return()=>clearTimeout(t)},[result]);

  const handleFileChange=e=>{const f=e.target.files?.[0];setError("");setResult(null);if(!f){setFile(null);return}if(!f.name.toLowerCase().endsWith(".eml")){setError("Please select a valid .eml file.");setFile(null);return}setFile(f)};
  const analyzeEmail=async()=>{if(!file){setError("Please select an .eml file first.");return}setLoading(true);setError("");setResult(null);try{const fd=new FormData();fd.append("file",file);const r=await fetch(`${API_BASE}/api/email/analyze`,{method:"POST",body:fd});if(!r.ok)throw new Error(`Server returned ${r.status}`);const d=await r.json();if(!d.success)throw new Error("Email analysis failed.");setResult(d.analysis)}catch(e){setError(e.message||"Unable to connect to the backend. Make sure FastAPI is running.")}finally{setLoading(false)}};
  const downloadReport=async()=>{if(!result)return;try{const r=await fetch(`${API_BASE}/api/email/report`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(result)});if(!r.ok)throw new Error(`Report generation failed (${r.status})`);const b=await r.blob(),u=window.URL.createObjectURL(b),a=document.createElement("a");a.href=u;a.download=`${result.filename?.replace(/\.eml$/i,"")||"email"}_forensic_report.pdf`;document.body.appendChild(a);a.click();a.remove();window.URL.revokeObjectURL(u)}catch(e){setError(e.message||"Unable to generate the forensic report.")}};
  const riskClass=r=>r==="CRITICAL"?"critical":r==="HIGH"?"high":r==="MEDIUM"?"medium":"low";
  const authState=v=>{const n=String(v||"unknown").toLowerCase();if(n==="pass")return{className:"auth-pass",icon:"✓",label:"PASS"};if(["fail","softfail","permerror","temperror"].includes(n))return{className:"auth-fail",icon:"✕",label:"FAIL"};return{className:"auth-unknown",icon:"?",label:"UNKNOWN"}};
  const groupedIndicators=Object.values((result?.indicators||[]).reduce((g,i)=>{const t=i.type||"UNKNOWN";if(!g[t])g[t]={...i,count:0};g[t].count++;return g},{}));
  const reputationCount=(result?.ip_reputation?.length||0)+(result?.domain_reputation?.length||0)+(result?.url_reputation?.length||0);
  const originIp=result?.origin_analysis?.earliest_reliable_ip;
  const originIntel=result?.ip_intelligence?.find(i=>i.ip===originIp);
  const originGeo=originIntel?.enrichment?.available?originIntel.enrichment:null;
  const relayHops=(result?.origin_analysis?.global_ips||[]).slice().sort((a,b)=>a.hop-b.hop).map(h=>{const i=result?.ip_intelligence?.find(x=>x.ip===h.ip),e=i?.enrichment||{},g=i?.geolocation||{};return{hop:h.hop,ip:h.ip,geo:{latitude:e.available?e.latitude:g.latitude??null,longitude:e.available?e.longitude:g.longitude??null,city:e.available?e.city:g.city??null,country:e.available?e.country:g.country??null,organization:e.available?e.organization:i?.reverse_dns?.hostname||null,provider:e.available?e.provider:null}}});

  return <div className="app">
    <header className="header"><div className="brand"><div className="brand-icon"><ShieldAlert size={25}/></div><div><h1>Email Threat Detection</h1><p>AI-Powered Email Forensics & Threat Intelligence</p></div></div><div className="status"><span className="status-dot"/> System Online</div></header>
    <main className="container">
      <section className="upload-card"><div className="upload-icon"><Upload size={30}/></div><div className="eyebrow">FORENSIC ANALYSIS PLATFORM</div><h2>Analyze an Email</h2><p>Upload an <strong>.eml</strong> file for header forensics, URL and attachment analysis, threat intelligence, origin analysis and Gemini AI investigation.</p><label className="file-input"><input type="file" accept=".eml,message/rfc822" onChange={handleFileChange}/><Upload size={18}/><span>{file?file.name:"Choose an .eml file"}</span></label>{file&&<div className="selected-file"><Mail size={16}/><span>{file.name}</span><span className="file-size">{(file.size/1024).toFixed(1)} KB</span></div>}<button className="analyze-button" onClick={analyzeEmail} disabled={!file||loading}>{loading?"Analyzing Email...":"Analyze Email"}{!loading&&<ChevronRight size={18}/>}</button>{error&&<div className="error"><AlertTriangle size={18}/>{error}</div>}</section>

      {result&&<div className="dashboard">
        <section className="dashboard-intro"><div><div className="eyebrow">ANALYSIS COMPLETE</div><h2>Forensic Investigation</h2><p>{result.filename||"Analyzed email"}</p></div><div className="analysis-status"><ShieldCheck size={17}/> Evidence collected</div></section>
        <section className="threat-card"><div className="section-title"><ShieldAlert size={21}/><span>Threat Overview</span></div><div className="threat-grid"><div className={`risk-box ${riskClass(result.threat_assessment?.risk_level)}`}><span className="label">RISK LEVEL</span><strong>{result.threat_assessment?.risk_level||"UNKNOWN"}</strong><small>Confidence: {Math.round((result.threat_assessment?.confidence||0)*100)}%</small></div><div className="score-box"><span className="label">THREAT SCORE</span><div className="score-display"><strong>{result.threat_assessment?.score??0}</strong><span>/100</span></div><div className="score-bar"><div style={{width:`${scoreWidth}%`}}/></div><div className="score-scale"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div></div><div className="verdict-box"><span className="label">VERDICT</span><strong>{result.threat_assessment?.verdict||"UNKNOWN"}</strong><small>Deterministic analysis</small></div></div><div className="classification-grid"><div className="classification"><span>Attack Type</span><strong>{result.attack_type_assessment?.attack_type||"—"}</strong></div><div className="classification"><span>Phishing</span><strong>{result.phishing_assessment?.classification||"—"}</strong></div><div className="classification"><span>Social Engineering</span><strong className={result.social_engineering_assessment?.social_engineering?"danger-text":"safe-text"}>{result.social_engineering_assessment?.social_engineering?"YES":"NO"}</strong></div></div></section>

        <section className="snapshot-grid"><div className="snapshot-card"><div className="snapshot-icon"><LinkIcon size={18}/></div><span>URLs</span><strong>{result.urls?.length||0}</strong><small>Analyzed</small></div><div className="snapshot-card"><div className="snapshot-icon"><Paperclip size={18}/></div><span>Attachments</span><strong>{result.attachments?.length||0}</strong><small>Detected</small></div><div className="snapshot-card"><div className="snapshot-icon"><AlertTriangle size={18}/></div><span>Indicators</span><strong>{result.indicators?.length||0}</strong><small>Threat signals</small></div><div className="snapshot-card"><div className="snapshot-icon"><Globe2 size={18}/></div><span>Reputation Checks</span><strong>{reputationCount}</strong><small>Provider results</small></div></section>

        <section className="card"><div className="section-title"><Mail size={21}/><span>Email Details</span></div><div className="details-grid"><div><span>Sender</span><strong>{result.headers?.from||"—"}</strong></div><div><span>Recipient</span><strong>{result.headers?.to||"—"}</strong></div><div><span>Reply-To</span><strong>{result.headers?.reply_to||"None"}</strong></div><div><span>Subject</span><strong>{result.headers?.subject||"—"}</strong></div></div></section>

        <section className="card"><div className="section-title"><LockKeyhole size={21}/><span>Email Authentication</span><span className="section-note">SPF / DKIM / DMARC</span></div><div className="authentication-grid">{["spf","dkim","dmarc"].map(n=>{const s=authState(result.authentication?.[n]);return <div className={`auth-box ${s.className}`} key={n}><span>{n.toUpperCase()}</span><strong>{s.icon} {s.label}</strong></div>})}</div></section>

        <section className="card origin-card">
          <div className="section-title"><Fingerprint size={21}/><span>Origin</span><span className="section-note">Sender identity & relay path</span></div>
          <div className="origin-grid">
            <div className="origin-box"><span>Sender Domain</span><strong>{result.domains?.sender_domain||"—"}</strong><small>Reply-To: {result.domains?.reply_to_domain||"—"}</small></div>
            <div className="origin-box"><span>Earliest Reliable IP</span><strong>{originIp||"No reliable public origin IP"}</strong><small>Confidence: {Math.round((result.origin_analysis?.confidence||0)*100)}%</small></div>
          </div>
          {result.origin_analysis?.reason&&<p className="origin-reason">{result.origin_analysis.reason}</p>}
          {(originGeo||relayHops.length>0)&&<div className="origin-map-wrapper"><OriginMap origin={originGeo} hops={relayHops}/></div>}
        </section>

        <section className="ai-card"><div className="section-title"><Brain size={22}/><span>AI Investigation</span>{result.llm_investigation?.enabled&&<span className="ai-badge">Gemini AI</span>}</div>{result.llm_investigation?.enabled&&result.llm_investigation?.analysis?<><div className="ai-summary"><h3>Executive Assessment</h3><p>{result.llm_investigation.analysis.executive_assessment}</p></div><div className="ai-columns"><div><h3>Key Evidence</h3><ul>{result.llm_investigation.analysis.key_evidence?.map((x,i)=><li key={i}>{x}</li>)}</ul></div><div><h3>Social Engineering</h3><div className="techniques">{result.llm_investigation.analysis.social_engineering_techniques?.map(x=><span key={x}>{x}</span>)}</div></div></div><div className="recommendations"><h3>Recommended Actions</h3><ul>{result.llm_investigation.analysis.recommended_actions?.map((x,i)=><li key={i}>{x}</li>)}</ul></div></>:<p className="ai-unavailable">AI investigation is currently unavailable.</p>}</section>

        <section className="card"><div className="section-title"><LinkIcon size={21}/><span>URL Intelligence</span><span className="section-note">{result.urls?.length||0} detected</span></div>{result.urls?.length?result.urls.map((u,i)=><div className="url-row" key={`${u.url}-${i}`}><div><strong>{u.url}</strong><span>{u.domain||"Unknown domain"}</span></div><span className="safe-badge">{u.threat_detected?"Threat Detected":"No Threat Detected"}</span></div>):<p className="muted">No URLs detected.</p>}</section>

        <section className="card"><div className="section-title"><AlertTriangle size={21}/><span>Threat Indicators</span><span className="indicator-count">{groupedIndicators.length}</span></div>{groupedIndicators.length?<div className="indicator-list">{groupedIndicators.map(i=><div className="indicator" key={i.type}><div><strong>{i.type}</strong>{i.count>1&&<span className="indicator-occurrences">{i.count} occurrences</span>}<p>{i.description}</p></div><span className={`severity ${(i.severity||"low").toLowerCase()}`}>{i.severity||"LOW"}</span></div>)}</div>:<div className="empty-state"><ShieldCheck size={20}/>No threat indicators detected.</div>}</section>

        <section className="report-card"><div><div className="eyebrow">FINAL EVIDENCE PACKAGE</div><h2>Ready for forensic reporting?</h2><p>Export the complete analysis, evidence, reputation results and AI investigation as a PDF.</p></div><button className="download-report-button" onClick={downloadReport}><Download size={18}/>Download Forensic Report</button></section>
      </div>}
    </main>
  </div>;
}
export default App;
