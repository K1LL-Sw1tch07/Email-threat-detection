from pathlib import Path
import shutil
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.parser.eml_parser import parse_eml


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

        # Parse the email
        result = parse_eml(temp_path)

        # Preserve the original uploaded filename
        result["filename"] = file.filename

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