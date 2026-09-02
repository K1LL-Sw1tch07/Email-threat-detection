from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.forensic.origin_analysis import analyze_origin
from app.schemas import AnalyzeEmailResponse
from app.forensic.correlation import correlate_email
from app.forensic.domain_intelligence import analyze_domain
from app.forensic.ip_intelligence import analyze_received_chain

from app.analyzer.content_analyzer import analyze_content
from app.analyzer.attachment_analyzer import analyze_attachments
from app.parser.eml_parser import parse_eml
from app.analyzer.header_analyzer import analyze_headers
from app.analyzer.url_analyzer import analyze_urls
from app.analyzer.scoring import calculate_threat_score

from app.intelligence.ip_reputation import check_ip_reputation
from app.intelligence.domain_reputation import check_domain_reputation
from app.intelligence.url_reputation import check_url_reputation
from app.intelligence.reputation_aggregator import aggregate_reputation

from app.ai.pipeline import run_ai_analysis


app = FastAPI(
    title="Email Threat Detection API",
    description="AI-powered Email Threat Detection and Forensic Intelligence Platform",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "message": "Email Threat Detection API",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post(
    "/api/email/analyze",
    response_model=AnalyzeEmailResponse
)
async def analyze_email(file: UploadFile = File(...)):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided."
        )

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    temp_path = None

    try:

        # -----------------------------------------
        # Temporary file
        # -----------------------------------------
        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".eml"
        ) as temp_file:

            shutil.copyfileobj(
                file.file,
                temp_file
            )

            temp_path = Path(temp_file.name)

        # -----------------------------------------
        # Parse the email
        # -----------------------------------------
        result = parse_eml(temp_path)

        # Preserve original filename
        result["filename"] = file.filename

        # -----------------------------------------
        # Header analysis
        # -----------------------------------------
        header_indicators = analyze_headers(
            result
        )

        # -----------------------------------------
        # URL analysis
        # -----------------------------------------
        url_indicators = analyze_urls(
            result.get("urls", [])
        )

        # -----------------------------------------
        # Domain intelligence
        # -----------------------------------------
        domain_intelligence = []

        seen_domains = set()

        for url_data in result.get("urls", []):

            domain = url_data.get("domain")

            if not domain:
                continue

            domain = domain.lower().rstrip(".")

            if domain in seen_domains:
                continue

            seen_domains.add(domain)

            domain_intelligence.append(
                analyze_domain(domain)
            )

        result["domain_intelligence"] = (
            domain_intelligence
        )

        # -----------------------------------------
        # Attachment analysis
        # -----------------------------------------
        attachment_indicators = analyze_attachments(
            result.get("attachments", [])
        )

        # -----------------------------------------
        # Content analysis
        # -----------------------------------------
        content_indicators = analyze_content(
            result.get("body", {}),
            result.get("headers", {}).get("subject", "")
        )

        # -----------------------------------------
        # IP forensic intelligence
        # -----------------------------------------
        ip_intelligence = analyze_received_chain(
            result.get("received_chain", [])
        )

        origin_analysis = analyze_origin(
            result.get("received_chain", [])
        )

        result["ip_intelligence"] = ip_intelligence
        result["origin_analysis"] = origin_analysis

        # -----------------------------------------
        # Email correlation
        # -----------------------------------------
        result["correlations"] = correlate_email(
            result
        )

        # -----------------------------------------
        # Threat Intelligence Reputation Analysis
        # -----------------------------------------

        ip_reputation_results = []
        domain_reputation_results = []
        url_reputation_results = []

        # -----------------------------------------
        # IP reputation
        # -----------------------------------------
        for ip_data in ip_intelligence:

            ip = ip_data.get("ip")

            if not ip:
                continue

            # Only query reputation providers
            # for public/global IPs
            if not ip_data.get("is_global"):
                continue

            reputation = check_ip_reputation(ip)

            if reputation.get("found"):
                ip_reputation_results.append(
                    reputation
                )

        # -----------------------------------------
        # Domain reputation
        # -----------------------------------------
        domains_to_check = set()

        # Sender domain
        sender_domain = (
            result
            .get("domains", {})
            .get("sender_domain")
        )

        if sender_domain:
            domains_to_check.add(
                sender_domain.lower().rstrip(".")
            )

        # Domains found in URLs
        for url_data in result.get("urls", []):

            domain = url_data.get("domain")

            if domain:
                domains_to_check.add(
                    domain.lower().rstrip(".")
                )

        # Check each unique domain
        for domain in domains_to_check:

            reputation = check_domain_reputation(
                domain
            )

            if reputation.get("found"):
                domain_reputation_results.append(
                    reputation
                )

        # -----------------------------------------
        # URL reputation
        # -----------------------------------------
        for url_data in result.get("urls", []):

            url = url_data.get("url")

            if not url:
                continue

            reputation = check_url_reputation(
                url
            )

            if reputation.get("found"):
                url_reputation_results.append(
                    reputation
                )

        # -----------------------------------------
        # Aggregate reputation findings
        # -----------------------------------------
        reputation_indicators = aggregate_reputation(
            ip_results=ip_reputation_results,
            domain_results=domain_reputation_results,
            url_results=url_reputation_results
        )

        # -----------------------------------------
        # Store raw reputation intelligence
        # -----------------------------------------
        result["ip_reputation"] = (
            ip_reputation_results
        )

        result["domain_reputation"] = (
            domain_reputation_results
        )

        result["url_reputation"] = (
            url_reputation_results
        )

        result["reputation_indicators"] = (
            reputation_indicators
        )

        # -----------------------------------------
        # Combine all indicators
        # -----------------------------------------
        result["indicators"] = (
            header_indicators
            + url_indicators
            + attachment_indicators
            + content_indicators
            + reputation_indicators
        )

        # -----------------------------------------
        # Calculate deterministic threat score
        # -----------------------------------------
        result["threat_assessment"] = (
            calculate_threat_score(
                result["indicators"]
            )
        )

        # -----------------------------------------
        # AI Analysis Pipeline
        # -----------------------------------------
        ai_result = run_ai_analysis(
            result
        )

        result["ai_evidence"] = (
            ai_result["ai_evidence"]
        )

        result["phishing_assessment"] = (
            ai_result["phishing_assessment"]
        )

        result["social_engineering_assessment"] = (
            ai_result[
                "social_engineering_assessment"
            ]
        )

        result["attack_type_assessment"] = (
            ai_result[
                "attack_type_assessment"
            ]
        )

        result["investigation_summary"] = (
            ai_result[
                "investigation_summary"
            ]
        )
        result["llm_investigation"] = (
             ai_result["llm_investigation"]
)

        # -----------------------------------------
        # Return result
        # -----------------------------------------
        return {
            "success": True,
            "analysis": result
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse EML file: {error}"
        )

    finally:

        if temp_path and temp_path.exists():
            temp_path.unlink()