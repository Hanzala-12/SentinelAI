from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from backend.api.schemas.scans import DetectedIssue
from backend.services.threat_intel.cache import ThreatIntelCache
from backend.services.threat_intel.models import ProviderFinding, ThreatIntelResult
from backend.services.threat_intel.providers.abuseipdb import AbuseIpDbClient
from backend.services.threat_intel.providers.urlscan import UrlScanClient
from backend.services.threat_intel.providers.virustotal import VirusTotalClient


class ThreatIntelService:
    def __init__(self) -> None:
        self.offline_eval = os.getenv("PHISHLENS_OFFLINE_EVAL", "0") == "1"
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.urlscan_key = os.getenv("URLSCAN_API_KEY")
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.cache = ThreatIntelCache()
        self.virustotal_client = VirusTotalClient(self.virustotal_key) if self.virustotal_key else None
        self.urlscan_client = UrlScanClient(self.urlscan_key) if self.urlscan_key else None
        self.abuseipdb_client = AbuseIpDbClient(self.abuseipdb_key) if self.abuseipdb_key else None

    def lookup_url(self, url: str | None) -> ThreatIntelResult:
        if self.offline_eval:
            return ThreatIntelResult(
                score=0,
                confidence=0.0,
                issues=[],
                notes=["Threat intelligence disabled for offline evaluation mode."],
                provider_findings=[],
            )

        if not url:
            return ThreatIntelResult(
                score=0,
                confidence=0.0,
                issues=[],
                notes=["Threat intelligence lookup skipped because no URL was provided."],
                provider_findings=[],
            )

        cached = self.cache.get(url)
        if cached:
            return cached  # type: ignore[return-value]

        issues: list[DetectedIssue] = []
        notes: list[str] = []
        provider_findings: list[ProviderFinding] = []

        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()

        tasks: list[tuple[str, str, callable]] = []

        if self.virustotal_client:
            tasks.append(("virustotal", "VirusTotal", lambda: self._query_virustotal(url)))
        else:
            notes.append("VirusTotal integration is not configured.")

        if self.urlscan_client:
            tasks.append(("urlscan", "URLScan", lambda: self._query_urlscan(url)))
        else:
            notes.append("URLScan integration is not configured.")

        if self.abuseipdb_client:
            ip_address = self._resolve_ip(hostname)
            if ip_address:
                tasks.append(("abuseipdb", "AbuseIPDB", lambda ip=ip_address: self._query_abuseipdb(ip)))
            else:
                notes.append("AbuseIPDB lookup skipped because hostname could not be resolved to a public IP.")
        else:
            notes.append("AbuseIPDB integration is not configured.")

        if tasks:
            with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
                future_map = {
                    executor.submit(task): (provider_key, provider_label)
                    for provider_key, provider_label, task in tasks
                }
                for future in as_completed(future_map):
                    provider_key, provider_label = future_map[future]
                    try:
                        finding, provider_issues, note = future.result()
                    except Exception as exc:
                        finding = ProviderFinding(
                            provider=provider_key,
                            score=0,
                            confidence=0.2,
                            summary=f"{provider_label} lookup failed: {exc}",
                            verdict="error",
                        )
                        provider_issues = []
                        note = f"{provider_label} lookup failed gracefully; no score contributed."
                    provider_findings.append(finding)
                    issues.extend(provider_issues)
                    if note:
                        notes.append(note)

        score = self._score_from_provider_findings(provider_findings)
        confidence = self._confidence_from_provider_findings(provider_findings)

        if not (self.virustotal_client or self.urlscan_client or self.abuseipdb_client):
            notes.append("No threat-intelligence providers are configured; using only local detection signals.")

        result = ThreatIntelResult(
            score=score,
            confidence=confidence,
            issues=issues,
            notes=notes,
            provider_findings=provider_findings,
        )
        self.cache.set(url, result)
        return result

    def _query_virustotal(self, url: str) -> tuple[ProviderFinding, list[DetectedIssue], str | None]:
        if not self.virustotal_client:
            return self._empty_finding("virustotal"), [], None

        try:
            data = asyncio.run(self.virustotal_client.lookup_url(url))
        except Exception as exc:
            return (
                ProviderFinding(
                    provider="virustotal",
                    score=0,
                    confidence=0.2,
                    summary=f"VirusTotal lookup failed: {exc}",
                    verdict="error",
                ),
                [],
                "VirusTotal lookup failed gracefully; continuing with remaining providers.",
            )

        stats = data.get("data", {}).get("attributes", {}).get("stats", {}) if isinstance(data, dict) else {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)

        confidence = min(0.97, 0.58 + min(25, malicious + suspicious) * 0.015)
        score = min(100, malicious * 22 + suspicious * 11)
        verdict = "clean"
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"

        summary = (
            f"VT detections: malicious={malicious}, suspicious={suspicious}, "
            f"harmless={harmless}, undetected={undetected}"
        )
        finding = ProviderFinding(
            provider="virustotal",
            score=score,
            confidence=confidence,
            summary=summary,
            verdict=verdict,
        )

        issues: list[DetectedIssue] = []
        if malicious > 0:
            severity = "critical" if malicious >= 3 else "high"
            issues.append(
                DetectedIssue(
                    code="reputation-virustotal-malicious",
                    title="VirusTotal malicious detections",
                    description=f"VirusTotal reports {malicious} malicious engine detections for this URL.",
                    severity=severity,
                )
            )
        elif suspicious > 0:
            issues.append(
                DetectedIssue(
                    code="reputation-virustotal-suspicious",
                    title="VirusTotal suspicious detections",
                    description=f"VirusTotal reports {suspicious} suspicious engine detections for this URL.",
                    severity="medium",
                )
            )

        note = None
        if verdict == "clean":
            note = "VirusTotal did not flag this URL as malicious at query time."
        return finding, issues, note

    def _query_urlscan(self, url: str) -> tuple[ProviderFinding, list[DetectedIssue], str | None]:
        if not self.urlscan_client:
            return self._empty_finding("urlscan"), [], None

        try:
            data = asyncio.run(self.urlscan_client.lookup_url(url))
        except Exception as exc:
            return (
                ProviderFinding(
                    provider="urlscan",
                    score=0,
                    confidence=0.2,
                    summary=f"URLScan submission failed: {exc}",
                    verdict="error",
                ),
                [],
                "URLScan lookup failed gracefully; no score contributed.",
            )

        verdict = "submitted"
        score = 0
        confidence = 0.45
        summary = "URL submitted to URLScan."
        if isinstance(data, dict):
            uuid = data.get("uuid")
            result_url = data.get("result")
            message = data.get("message")
            if message:
                summary = f"URLScan response: {message}"
            if uuid and result_url:
                summary = f"URLScan submission accepted (uuid={uuid}). Result: {result_url}"
            verdicts = data.get("verdicts") or {}
            overall = verdicts.get("overall") if isinstance(verdicts, dict) else None
            if isinstance(overall, dict):
                score = min(100, int(overall.get("score", 0) or 0))
                if score >= 65:
                    verdict = "malicious"
                elif score >= 35:
                    verdict = "suspicious"
                else:
                    verdict = "clean"
                confidence = 0.65

        issues: list[DetectedIssue] = []
        if verdict == "malicious":
            issues.append(
                DetectedIssue(
                    code="reputation-urlscan-malicious",
                    title="URLScan malicious verdict",
                    description=summary,
                    severity="high",
                )
            )
        elif verdict == "suspicious":
            issues.append(
                DetectedIssue(
                    code="reputation-urlscan-suspicious",
                    title="URLScan suspicious verdict",
                    description=summary,
                    severity="medium",
                )
            )

        note = "URLScan requires asynchronous result review for deeper behavioral verdicts."
        return (
            ProviderFinding(
                provider="urlscan",
                score=score,
                confidence=confidence,
                summary=summary,
                verdict=verdict,
            ),
            issues,
            note,
        )

    def _query_abuseipdb(self, ip_address: str) -> tuple[ProviderFinding, list[DetectedIssue], str | None]:
        if not self.abuseipdb_client:
            return self._empty_finding("abuseipdb"), [], None

        try:
            data = asyncio.run(self.abuseipdb_client.lookup_ip(ip_address))
        except Exception as exc:
            return (
                ProviderFinding(
                    provider="abuseipdb",
                    score=0,
                    confidence=0.2,
                    summary=f"AbuseIPDB lookup failed: {exc}",
                    verdict="error",
                ),
                [],
                "AbuseIPDB lookup failed gracefully; no score contributed.",
            )

        raw = data.get("data", {}) if isinstance(data, dict) else {}
        abuse_score = int(raw.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(raw.get("totalReports", 0) or 0)
        usage_type = str(raw.get("usageType", "unknown"))

        verdict = "clean"
        if abuse_score >= 75:
            verdict = "malicious"
        elif abuse_score >= 30:
            verdict = "suspicious"

        summary = (
            f"AbuseIPDB for {ip_address}: abuseConfidenceScore={abuse_score}, "
            f"totalReports={total_reports}, usageType={usage_type}"
        )

        finding = ProviderFinding(
            provider="abuseipdb",
            score=min(100, abuse_score),
            confidence=min(0.95, 0.55 + min(40, total_reports) * 0.01),
            summary=summary,
            verdict=verdict,
        )

        issues: list[DetectedIssue] = []
        if abuse_score >= 75:
            issues.append(
                DetectedIssue(
                    code="reputation-abuseipdb-high",
                    title="High abuse confidence IP",
                    description=f"Resolved host IP {ip_address} has AbuseIPDB confidence score {abuse_score}.",
                    severity="high",
                )
            )
        elif abuse_score >= 30:
            issues.append(
                DetectedIssue(
                    code="reputation-abuseipdb-medium",
                    title="Moderate abuse confidence IP",
                    description=f"Resolved host IP {ip_address} has AbuseIPDB confidence score {abuse_score}.",
                    severity="medium",
                )
            )

        return finding, issues, None

    def _resolve_ip(self, hostname: str) -> str | None:
        if not hostname:
            return None
        try:
            ipaddress.ip_address(hostname)
            return hostname
        except ValueError:
            pass

        try:
            resolved = socket.gethostbyname(hostname)
        except Exception:
            return None

        try:
            parsed = ipaddress.ip_address(resolved)
            if parsed.is_private or parsed.is_loopback:
                return None
            return resolved
        except ValueError:
            return None

    def _score_from_provider_findings(self, findings: list[ProviderFinding]) -> int:
        active_scores = [finding.score for finding in findings if finding.verdict not in {"error", "submitted"}]
        if not active_scores:
            return 0
        strongest = max(active_scores)
        corroborated = sum(1 for score in active_scores if score >= 45)
        return min(100, strongest + max(0, corroborated - 1) * 8)

    def _confidence_from_provider_findings(self, findings: list[ProviderFinding]) -> float:
        active = [finding for finding in findings if finding.verdict != "error"]
        if not active:
            return 0.2
        average = sum(finding.confidence for finding in active) / len(active)
        return round(max(0.25, min(0.99, average)), 2)

    def _empty_finding(self, provider: str) -> ProviderFinding:
        return ProviderFinding(
            provider=provider,
            score=0,
            confidence=0.0,
            summary=f"{provider} not configured.",
            verdict="unavailable",
        )
