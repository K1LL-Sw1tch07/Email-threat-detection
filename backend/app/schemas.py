from typing import Any

from pydantic import BaseModel, Field


class ThreatAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    risk_level: str
    verdict: str
    confidence: float = Field(ge=0.0, le=1.0)
    breakdown: list[dict[str, Any]]
    category_breakdown: list[dict[str, Any]]
    evidence: list[str]
    recommended_actions: list[str]


class AnalysisResponse(BaseModel):
    filename: str
    file_sha256: str
    headers: dict[str, Any]
    addresses: dict[str, Any]
    domains: dict[str, Any]
    authentication: dict[str, Any]
    received_chain: list[dict[str, Any]]
    body: dict[str, Any]
    urls: list[dict[str, Any]]
    attachments: list[dict[str, Any]]
    all_headers: list[dict[str, Any]]
    domain_intelligence: list[dict[str, Any]]
    ip_intelligence: list[dict[str, Any]]
    origin_analysis: dict[str, Any]
    correlations: dict[str, Any]
    indicators: list[dict[str, Any]]
    threat_assessment: ThreatAssessment


class AnalyzeEmailResponse(BaseModel):
    success: bool
    analysis: AnalysisResponse
