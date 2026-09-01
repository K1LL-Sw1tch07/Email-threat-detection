from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.forensic.domain_intelligence import analyze_domain
from app.forensic.ip_intelligence import analyze_received_chain
from app.analyzer.content_analyzer import analyze_content
from app.analyzer.attachment_analyzer import analyze_attachments
from app.parser.eml_parser import parse_eml
from app.analyzer.header_analyzer import analyze_headers
from app.analyzer.url_analyzer import analyze_urls
from app.analyzer.scoring import calculate_threat_score


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


@app.post("/api/email/analyze")
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

    # Temporary file
    temp_path = None

    try:

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

        # Header analysis
        header_indicators = analyze_headers(
            result
)

        # URL analysis
        url_indicators = analyze_urls(
            result.get("urls", [])
)
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

        result["domain_intelligence"] = domain_intelligence

        # Attachment analysis
        attachment_indicators = analyze_attachments(
            result.get("attachments", [])
)
        # Content analysis
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

        result["ip_intelligence"] = ip_intelligence

        # Combine all indicators
        result["indicators"] = (
            header_indicators +
            url_indicators +
            attachment_indicators+
            content_indicators
)

        # -----------------------------------------
        # Calculate threat score
        # -----------------------------------------

        result["threat_assessment"] = (
            calculate_threat_score(
                result["indicators"]
            )
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