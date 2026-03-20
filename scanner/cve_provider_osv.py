from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

from packaging.version import InvalidVersion, Version

from .models import Finding, Criticality
from .parser import normalize_package_name


class OsvcveProvider:

    OSV_QUERY_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self._timeout_seconds = float(timeout_seconds)
        self._cache: Dict[Tuple[str, str], List[Finding]] = {}

    def find_cve_findings(self, package_name: str, package_version: str) -> List[Finding]:
        name = normalize_package_name(package_name)
        version = (package_version or "").strip()

        # CVE-поиск без точной версии не выполняем
        if not version:
            self._cache[(name, version)] = []
            return []

        if any(op in version for op in ("<", ">", "=", "~", "!", ";", ",", " ")) and not version.replace(".", "").isdigit():
            self._cache[(name, version)] = []
            return []

        cache_key = (name, version)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return list(cached)

        vulns = self._query_osv(name=name, version=version)
        vulns = [v for v in vulns if self._vuln_affects_version(v, name, version)]
        findings: List[Finding] = [self._vuln_to_finding(name, version, v) for v in vulns]

        self._cache[cache_key] = list(findings)
        return findings

    def _query_osv(self, name: str, version: str) -> List[dict]:
        payload = {"package": {"ecosystem": "PyPI", "name": name}}
        if version:
            payload["version"] = version
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            self.OSV_QUERY_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                raw = resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            # Если OSV недоступен — не падаем, просто возвращаем пустой список
            return []

        try:
            obj = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []

        vulns = obj.get("vulns")
        if isinstance(vulns, list):
            return [x for x in vulns if isinstance(x, dict)]
        return []

    def _vuln_to_finding(self, package_name: str, package_version: str, vuln: dict) -> Finding:
        vuln_id = self._safe_str(vuln.get("id"))
        summary = self._safe_str(vuln.get("summary"))
        details = self._safe_str(vuln.get("details"))

        parts: List[str] = []
        if vuln_id:
            parts.append(f"OSV: {vuln_id}")
        if summary:
            parts.append(summary)
        elif details:
            parts.append(details)

        description = " — ".join([p for p in parts if p]) or "Обнаружены уязвимости по данным OSV для указанной версии."
        recommendation = "Обновить пакет до версии без уязвимости."
        criticality = self._extract_criticality(vuln)

        if vuln_id:
            reason = f"OSV вернул vulns (id={vuln_id}) для PyPI: {package_name} {package_version}"
        else:
            reason = f"OSV вернул vulns для PyPI: {package_name} {package_version}"

        return Finding(
            name=package_name,
            version=package_version,
            risk_type="CVE",
            description=description,
            recommendation=recommendation,
            criticality=criticality,
            reason=reason,
        )

    def _extract_criticality(self, vuln: dict) -> Criticality:
        dbs = vuln.get("database_specific")
        if isinstance(dbs, dict):
            mapped = self._map_severity_value(dbs.get("severity"))
            if mapped is not None:
                return mapped

        sev_list = vuln.get("severity")
        if isinstance(sev_list, list):
            for item in sev_list:
                if isinstance(item, dict):
                    mapped = self._map_severity_value(item.get("score"))
                    if mapped is not None:
                        return mapped

        return "Low"

    def _map_severity_value(self, value: object) -> Optional[Criticality]:
        if not isinstance(value, str):
            return None
        v = value.strip().upper()

        if v == "CRITICAL":
            return "Critical"
        if v == "HIGH":
            return "High"
        if v in ("MEDIUM", "MODERATE"):
            return "Medium"
        if v in ("LOW", "INFO", "INFORMATIONAL"):
            return "Low"
        return None

    def _vuln_affects_version(self, vuln: dict, pkg_name: str, version: str) -> bool:
        try:
            v = Version(version)
        except InvalidVersion:
            return True

        affected = vuln.get("affected")
        if not isinstance(affected, list) or not affected:
            return True

        matched_any = False
        for a in affected:
            if not isinstance(a, dict):
                continue
            pkg = a.get("package")
            if not isinstance(pkg, dict):
                continue
            eco = str(pkg.get("ecosystem") or "")
            name = normalize_package_name(str(pkg.get("name") or ""))
            if eco != "PyPI" or name != pkg_name:
                continue

            matched_any = True
            if self._affected_entry_contains_version(a, v):
                return True


        if not matched_any:
            return True
        return False

    def _affected_entry_contains_version(self, affected_entry: dict, v: Version) -> bool:
        versions = affected_entry.get("versions")
        if isinstance(versions, list) and versions:
            for s in versions:
                if isinstance(s, str):
                    try:
                        if Version(s) == v:
                            return True
                    except InvalidVersion:
                        continue

        ranges = affected_entry.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            return True

        for r in ranges:
            if not isinstance(r, dict):
                continue
            events = r.get("events")
            if not isinstance(events, list) or not events:
                continue
            if self._events_cover_version(events, v):
                return True

        return False

    def _events_cover_version(self, events: list, v: Version) -> bool:
        introduced: Optional[Version] = None
        fixed: Optional[Version] = None
        last_affected: Optional[Version] = None
        limit: Optional[Version] = None

        for e in events:
            if not isinstance(e, dict):
                continue
            if "introduced" in e and isinstance(e["introduced"], str):
                s = e["introduced"].strip()
                if s == "0":
                    introduced = None
                else:
                    try:
                        introduced = Version(s)
                    except InvalidVersion:
                        pass
            if "fixed" in e and isinstance(e["fixed"], str):
                try:
                    fixed = Version(e["fixed"].strip())
                except InvalidVersion:
                    pass
            if "last_affected" in e and isinstance(e["last_affected"], str):
                try:
                    last_affected = Version(e["last_affected"].strip())
                except InvalidVersion:
                    pass
            if "limit" in e and isinstance(e["limit"], str):
                try:
                    limit = Version(e["limit"].strip())
                except InvalidVersion:
                    pass

        if introduced is None and fixed is None and last_affected is None and limit is None:
            return True

        if introduced is not None and v < introduced:
            return False
        if fixed is not None and v >= fixed:
            return False
        if limit is not None and v >= limit:
            return False
        if last_affected is not None and v > last_affected:
            return False

        return True

    def _safe_str(self, v: object) -> str:
        return v.strip() if isinstance(v, str) else ""