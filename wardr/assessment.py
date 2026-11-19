"""Match software versions from a local CycloneDX BOM against imported OSV records."""

import hashlib
import json
import math
import os
import re
import stat
from collections import Counter, defaultdict
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote

_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 48 * 1024 * 1024
_MAX_FILES = 32
_MAX_COMPONENTS = 20_000
_MAX_RECORDS = 20_000
_MAX_COMPARISONS = 25_000
_MAX_RANGE_WORK = 2_000_000
_MAX_DETAILS = 500
_MAX_VERSION = 160
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}\Z")
_PACKAGE_TYPE = re.compile(r"[a-z][a-z0-9.-]{0,39}\Z")
_SCOPE = (
    "Assessment uses the versions recorded in the supplied CycloneDX inventory and the supplied "
    "OSV records. It evaluates enumerated versions, SemVer ranges, and numeric PyPI release ranges. "
    "Packages with no matching advisory entry remain outside the coverage of the imported data. "
    "CISA matches apply only to advisory IDs or aliases present in the supplied catalog."
)
_ECOSYSTEMS = {
    "crates.io": "cargo", "go": "golang", "hex": "hex", "homebrew": "brew",
    "maven": "maven", "npm": "npm", "nuget": "nuget", "packagist": "composer",
    "pub": "pub", "pypi": "pypi", "rubygems": "gem",
}
_DISTRO_TYPES = {"alpine": "apk", "debian": "deb", "ubuntu": "deb"}
_SUPPORTED_TYPES = set(_ECOSYSTEMS.values()) | set(_DISTRO_TYPES.values())
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_PYTHON_RELEASE = re.compile(r"(?:(\d+)!)?([0-9]+(?:\.[0-9]+)*)\Z", re.ASCII)
_CVSS_V3_VALUES = {
    "AV": {"N": .85, "A": .62, "L": .55, "P": .2},
    "AC": {"L": .77, "H": .44},
    "UI": {"N": .85, "R": .62},
    "C": {"N": 0, "L": .22, "H": .56},
    "I": {"N": 0, "L": .22, "H": .56},
    "A": {"N": 0, "L": .22, "H": .56},
}


class AssessmentError(ValueError):
    """The supplied assessment input cannot be evaluated."""


@dataclass(frozen=True)
class _Package:
    kind: str
    name: str
    qualifiers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _Component:
    package: _Package
    version: str
    purl: str


@dataclass(frozen=True)
class _Interval:
    start: tuple
    start_version: str
    end: tuple | None
    end_kind: str | None
    end_version: str | None


@dataclass(frozen=True)
class _VersionRange:
    kind: str
    parser: Callable[[str], tuple | None]
    intervals: tuple[_Interval, ...]
    limit: tuple | None


@dataclass(frozen=True)
class _Outcome:
    evidence: str | None
    confidence: str
    fixed: str | None
    gaps: tuple[str, ...]


def _display(value, limit):
    if not isinstance(value, str):
        return ""
    return "".join(char if char.isprintable() else " " for char in value[:limit]).strip()


def _version(value):
    if isinstance(value, str) and 0 < len(value) <= _MAX_VERSION and value == _display(value, _MAX_VERSION):
        return value
    return None


def _purl_segment(value):
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Invalid Package URL encoding.")
    decoded = unquote(value, errors="strict")
    if not decoded or decoded != _display(decoded, 1500):
        raise ValueError("Invalid Package URL component.")
    return decoded


def _identity_name(kind, path):
    if any("/" in item or item in (".", "..") for item in path):
        raise ValueError("Invalid Package URL path.")
    if kind == "pypi":
        if len(path) != 1 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", path[0]):
            raise ValueError("Invalid PyPI package.")
        return re.sub(r"[-_.]+", "-", path[0]).lower()
    if kind == "maven":
        if len(path) != 2 or any(":" in item for item in path):
            raise ValueError("Invalid Maven package.")
        return ":".join(path)
    if kind == "npm":
        if len(path) not in (1, 2) or (len(path) == 2) != path[0].startswith("@"):
            raise ValueError("Invalid npm package scope.")
    if kind in ("cargo", "gem", "nuget", "pub") and len(path) != 1:
        raise ValueError("Unexpected package namespace.")
    name = "/".join(path)
    return name.lower() if kind in ("npm", "nuget", "composer") else name


def _parse_purl(value):
    if not isinstance(value, str) or len(value) > 1500 or not value.startswith("pkg:"):
        raise ValueError("Missing Package URL.")
    without_fragment, delimiter, _ = value.partition("#")
    if delimiter:
        raise ValueError("Package URL refers to a subpath.")
    path, _, query = without_fragment[4:].partition("?")
    version_at = path.rfind("@")
    version = None
    if version_at > path.rfind("/"):
        version = _version(_purl_segment(path[version_at + 1:]))
        if version is None:
            raise ValueError("Invalid Package URL version.")
        path = path[:version_at]
    kind, separator, path = path.partition("/")
    kind = kind.lower()
    if not separator or not _PACKAGE_TYPE.fullmatch(kind) or kind not in _SUPPORTED_TYPES:
        raise ValueError("Unsupported Package URL type.")
    name = _identity_name(kind, [_purl_segment(item) for item in path.split("/")])
    qualifiers = {}
    for qualifier in query.split("&") if query else ():
        key, separator, raw = qualifier.partition("=")
        key = key.lower()
        if not separator or key in qualifiers or not re.fullmatch(r"[a-z][a-z0-9._-]*", key):
            raise ValueError("Invalid Package URL qualifier.")
        qualifiers[key] = _purl_segment(raw)
    return _Package(kind, name, tuple(sorted(qualifiers.items()))), version


def _inventory(document):
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise AssessmentError("Choose a CycloneDX JSON bill of materials.")
    stack = []
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        stack.append(metadata["component"])
    components = document.get("components", [])
    if not isinstance(components, list):
        raise AssessmentError("CycloneDX components must be an array.")
    if len(components) > _MAX_COMPONENTS:
        raise AssessmentError(f"The inventory exceeds {_MAX_COMPONENTS:,} components.")
    stack.extend(reversed(components))
    counts = Counter()
    entries = defaultdict(dict)
    while stack:
        item = stack.pop()
        counts["components"] += 1
        if counts["components"] > _MAX_COMPONENTS:
            raise AssessmentError(f"The inventory exceeds {_MAX_COMPONENTS:,} components.")
        if not isinstance(item, dict):
            counts["invalid_component"] += 1
            continue
        children = item.get("components", [])
        if not isinstance(children, list):
            counts["invalid_component"] += 1
            continue
        if counts["components"] + len(stack) + len(children) > _MAX_COMPONENTS:
            raise AssessmentError(f"The inventory exceeds {_MAX_COMPONENTS:,} components.")
        stack.extend(reversed(children))
        try:
            package, embedded = _parse_purl(item.get("purl"))
        except ValueError:
            counts["missing_or_unsupported_purl"] += 1
            continue
        version = _version(item.get("version")) if "version" in item else embedded
        if not version or embedded and _canonical_version(package, embedded) != _canonical_version(package, version):
            counts["missing_or_conflicting_version"] += 1
            continue
        identity_version = _canonical_version(package, version)
        entries[package].setdefault(identity_version, _Component(package, version, item["purl"]))
        counts["identified_components"] += 1
    return entries, {
        "components": counts["components"],
        "identified_components": counts["identified_components"],
        "identified_packages": sum(len(versions) for versions in entries.values()),
        "skipped_components": counts["components"] - counts["identified_components"],
        "skip_reasons": {
            key: counts[key] for key in (
                "invalid_component", "missing_or_unsupported_purl", "missing_or_conflicting_version",
            ) if counts[key]
        },
    }


def _affected_package(affected):
    descriptor = affected.get("package")
    if not isinstance(descriptor, dict):
        return None
    ecosystem = _display(descriptor.get("ecosystem"), 1500)
    ecosystem_type = _ECOSYSTEMS.get(ecosystem.casefold())
    name = _display(descriptor.get("name"), 1500)
    if not name:
        return None
    reference = None
    if ecosystem_type:
        try:
            pieces = name.split(":") if ecosystem_type == "maven" else name.split("/")
            reference = _Package(ecosystem_type, _identity_name(ecosystem_type, pieces))
        except ValueError:
            return None
    if "purl" not in descriptor:
        return (reference, ecosystem) if reference else None
    try:
        package, version = _parse_purl(descriptor["purl"])
    except ValueError:
        return None
    if version or reference and (package.kind, package.name) != (reference.kind, reference.name):
        return None
    qualifiers = dict(package.qualifiers)
    if not reference:
        # A release or alternate repository has its own advisory context.
        # Require the scoped ecosystem and PURL to agree before matching it.
        base, separator, scope = ecosystem.partition(":")
        base = base.lower()
        if not separator or not scope:
            return None
        distro_type = _DISTRO_TYPES.get(base)
        if distro_type:
            release = scope.removeprefix("v") if base == "alpine" else scope
            if (
                package.kind != distro_type or qualifiers.get("distro") != f"{base}-{release}"
                or package.name != f"{base}/{name}"
            ):
                return None
        else:
            kind = _ECOSYSTEMS.get(base)
            try:
                pieces = name.split(":") if kind == "maven" else name.split("/")
                expected = _identity_name(kind, pieces)
            except ValueError:
                return None
            if package.kind != kind or package.name != expected or qualifiers.get("repository_url") != scope:
                return None
    return package, ecosystem or package.kind


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40 or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _record_list(document):
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        if "id" in document:
            return [document]
        if isinstance(document.get("vulns"), list):
            return document["vulns"]
    raise AssessmentError("Choose OSV JSON records, a JSON array, or an OSV response with a vulns array.")


def _advisory_records(rows):
    if len(rows) > _MAX_RECORDS:
        raise AssessmentError(f"The assessment supports at most {_MAX_RECORDS:,} advisory records.")
    records = {}
    discarded = 0
    for row in rows:
        identifier = row.get("id") if isinstance(row, dict) else None
        modified = _timestamp(row.get("modified")) if isinstance(row, dict) else None
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier) or modified is None:
            discarded += 1
            continue
        if identifier not in records or modified > records[identifier][0]:
            records[identifier] = modified, row
        elif modified == records[identifier][0] and row != records[identifier][1]:
            raise AssessmentError(f"Conflicting OSV records for {identifier} have an identical modification time.")
    return (item[1] for item in records.values()), discarded


def _semver(value):
    if not value or len(value) > _MAX_VERSION:
        return None
    match = _SEMVER.fullmatch(value)
    if match is None:
        return None
    core = tuple(map(int, match.groups()[:3]))
    prerelease = match.group(4)
    if prerelease is None:
        return core, True, ()
    identifiers = []
    for item in prerelease.split("."):
        if item.isascii() and item.isdecimal():
            if len(item) > 1 and item.startswith("0"):
                return None
            identifiers.append((0, int(item)))
        else:
            identifiers.append((1, item))
    return core, False, tuple(identifiers)


def _pypi_release(value):
    match = _PYTHON_RELEASE.fullmatch(value or "")
    if match is None:
        return None
    release = list(map(int, match.group(2).split(".")))
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    return int(match.group(1) or "0"), tuple(release)


def _canonical_version(package, value):
    if package.kind == "golang" and value.startswith("v") and _semver(value[1:]) is not None:
        return value[1:]
    return value


def _intervals(entry, parse):
    events = entry.get("events")
    if not isinstance(events, list) or not events or len(events) > 1000:
        raise ValueError("Range event data is missing or exceeds the supported size.")
    timeline, limits = [], []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ValueError("A version boundary is malformed.")
        kind, raw = next(iter(event.items()))
        if kind not in ("introduced", "fixed", "last_affected", "limit") or _version(raw) is None:
            raise ValueError("A version boundary is malformed.")
        if kind == "limit" and raw == "*":
            limits.append(None)
            continue
        if kind == "introduced" and raw == "0":
            value = ()
        else:
            value = parse(raw)
            if value is None:
                raise ValueError("A published boundary uses an unsupported version format.")
        if kind == "limit":
            limits.append(value)
        else:
            timeline.append((value, kind, raw))
    kinds = {kind for _, kind, _ in timeline}
    if "introduced" not in kinds or {"fixed", "last_affected"} <= kinds:
        raise ValueError("Range events describe an unsupported version timeline.")
    active = None
    intervals = []
    for value, kind, raw in sorted(timeline, key=lambda item: (item[0], item[1] != "introduced")):
        if kind == "introduced":
            if active is not None:
                raise ValueError("Range introductions overlap.")
            active = (value, raw)
        elif active is None or value == active[0] and kind == "fixed":
            raise ValueError("Range closure does not follow an introduction.")
        else:
            intervals.append(_Interval(*active, value, kind, raw))
            active = None
    if active is not None:
        intervals.append(_Interval(*active, None, None, None))
    limit = max(limits) if limits and None not in limits else None
    return intervals, limit


def _compile_range(entry, package):
    if not isinstance(entry, dict):
        raise ValueError("Malformed advisory range.")
    kind = entry.get("type")
    if kind == "SEMVER":
        parse = _semver
    elif kind == "ECOSYSTEM" and package.kind == "pypi":
        parse = _pypi_release
    else:
        reason = _display(kind, 24) or "unknown"
        raise ValueError(f"{reason} range ordering is unavailable for this package type.")
    intervals, limit = _intervals(entry, parse)
    return _VersionRange(kind, parse, tuple(intervals), limit)


def _range_match(entry, version):
    installed = entry.parser(version)
    if installed is None:
        return None, None, "The inventory version uses an unsupported format for this range."
    if entry.limit is not None and installed >= entry.limit:
        return None, None, None
    for interval in entry.intervals:
        if installed < interval.start:
            break
        if interval.end is not None and (
            installed > interval.end if interval.end_kind == "last_affected" else installed >= interval.end
        ):
            continue
        start = interval.start_version
        description = "from the earliest recorded version" if start == "0" else f"introduced at {start}"
        fixed = None
        if interval.end_kind == "fixed":
            description += f" and fixed at {interval.end_version}"
            if entry.limit is None or interval.end <= entry.limit:
                fixed = interval.end_version
        elif interval.end_kind == "last_affected":
            description += f" through {interval.end_version} inclusive"
        return f"The inventory version is in a published {entry.kind} range {description}.", fixed, None
    return None, None, None


def _compile_affected(affected, package):
    reasons = set()
    raw_versions = affected.get("versions", [])
    raw_ranges = affected.get("ranges", [])
    versions = set()
    if isinstance(raw_versions, list):
        for version in raw_versions:
            if _version(version) is None:
                reasons.add("The affected version list contains invalid versions.")
            else:
                versions.add(_canonical_version(package, version))
    else:
        reasons.add("The affected version list is malformed.")
    if not isinstance(raw_ranges, list):
        reasons.add("The affected range list is malformed.")
        raw_ranges = []
    if not raw_ranges and not versions:
        reasons.add("This advisory entry supplies no affected versions or ranges.")
    if len(raw_ranges) > 100:
        raise AssessmentError("An advisory entry contains too many ranges to assess.")
    ranges = []
    for entry in raw_ranges:
        try:
            ranges.append(_compile_range(entry, package))
        except ValueError as exc:
            reasons.add(str(exc))
    return versions, ranges, reasons


def _version_match(versions, ranges, compile_reasons, component):
    version = _canonical_version(component.package, component.version)
    exact = version in versions
    reasons = set(compile_reasons)
    evidence = None
    fixes = set()
    for entry in ranges:
        match, fix, reason = _range_match(entry, version)
        if match:
            evidence = evidence or match
        if fix:
            fixes.add(fix)
        if reason:
            reasons.add(reason)
    if exact:
        evidence = "The inventory version exactly matches an explicitly listed affected version."
    fixed = None
    if len(fixes) == 1 and not reasons:
        candidate = next(iter(fixes))
        if candidate not in versions and not any(
            match or reason for match, _, reason in (_range_match(entry, candidate) for entry in ranges)
        ):
            fixed = candidate
    return _Outcome(evidence, "exact_version" if exact else "affected_range", fixed, tuple(sorted(reasons)))


def _cvss_v3(score):
    if not isinstance(score, str) or len(score) > 250:
        return None
    version, _, raw = score.partition("/")
    if version not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics = {}
    for entry in raw.split("/"):
        key, separator, value = entry.partition(":")
        if not separator or key in metrics:
            return None
        metrics[key] = value
    scope = metrics.get("S")
    if scope not in ("U", "C") or metrics.get("PR") not in ("N", "L", "H"):
        return None
    try:
        weights = {key: options[metrics[key]] for key, options in _CVSS_V3_VALUES.items()}
    except KeyError:
        return None
    privileges = {"N": .85, "L": .68 if scope == "C" else .62, "H": .50 if scope == "C" else .27}
    impact_ratio = 1 - math.prod(1 - weights[key] for key in ("C", "I", "A"))
    impact = (
        7.52 * (impact_ratio - .029) - 3.25 * (impact_ratio - .02) ** 15 if scope == "C"
        else 6.42 * impact_ratio
    )
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * weights["AV"] * weights["AC"] * privileges[metrics["PR"]] * weights["UI"]
    capped = min(10, (impact + exploitability) * (1.08 if scope == "C" else 1))
    return math.ceil(round(capped * 100_000) / 10_000) / 10


def _rating(severity):
    scores = []
    for item in severity if isinstance(severity, list) else ():
        if isinstance(item, dict) and item.get("type") == "CVSS_V3":
            value = _cvss_v3(item.get("score"))
            if value is not None:
                scores.append(value)
    return max(scores, default=None)


def _severity_label(score):
    if score is None or score <= 0:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _result(identifier, advisory, aliases, component, ecosystem, outcome, score, known_exploited):
    if outcome.fixed:
        remediation = (
            f"The advisory gives {outcome.fixed} as a fixed release boundary. "
            "Confirm compatibility, update to a supported fixed release, and regenerate the inventory."
        )
    else:
        remediation = "Review the publisher advisory for a supported fixed release, then regenerate the inventory."
    identity = component.package
    stable_key = [identifier, identity.kind, identity.name, identity.qualifiers, _canonical_version(identity, component.version)]
    opaque_id = hashlib.sha256(json.dumps(stable_key, ensure_ascii=True).encode("ascii")).hexdigest()[:24]
    return {
        "id": f"advisory-{opaque_id}",
        "advisory_id": identifier,
        "aliases": aliases[:20],
        "title": _display(advisory.get("summary"), 200) or f"Published advisory {identifier}",
        "package": component.package.name,
        "ecosystem": ecosystem,
        "version": component.version,
        "purl": component.purl,
        "severity": _severity_label(score),
        "cvss_base_score": score,
        "known_exploited": known_exploited,
        "evidence": outcome.evidence,
        "remediation": remediation,
        "fixed_versions": [outcome.fixed] if outcome.fixed else [],
        "confidence": outcome.confidence,
        "source_url": "https://osv.dev/vulnerability/" + quote(identifier, safe=""),
    }


def assess_documents(sbom: dict, advisories: dict | list, *, exploited_ids: Collection[str] = ()) -> dict:
    """Evaluate imported documents locally. The input inventory is never transmitted."""
    inventory_index, inventory = _inventory(sbom)
    raw = _record_list(advisories)
    records, discarded = _advisory_records(raw)
    known = {item.upper() for item in exploited_ids if isinstance(item, str)}
    matched_packages, covered_packages = set(), set()
    findings, gaps = [], []
    records_count = withdrawn = unevaluated = comparisons = gap_count = range_work = 0
    for advisory in records:
        records_count += 1
        identifier = advisory["id"]
        if "withdrawn" in advisory:
            withdrawn += 1
            continue
        aliases_data = advisory.get("aliases", [])
        aliases = sorted({
            alias for alias in aliases_data if isinstance(alias, str) and _ID.fullmatch(alias)
        }) if isinstance(aliases_data, list) else []
        known_exploited = any(item.upper() in known for item in (identifier, *aliases))
        affected_rows = advisory.get("affected") or []
        if not isinstance(affected_rows, list):
            unevaluated += 1
            continue
        candidates = defaultdict(list)
        for affected in affected_rows:
            parsed = _affected_package(affected) if isinstance(affected, dict) else None
            if parsed is None:
                unevaluated += 1
                continue
            package, ecosystem = parsed
            components = inventory_index.get(package)
            if not components:
                continue
            versions, ranges, reasons = _compile_affected(affected, package)
            comparisons += len(components)
            range_work += len(components) * sum(len(entry.intervals) + 1 for entry in ranges)
            if comparisons > _MAX_COMPARISONS or range_work > _MAX_RANGE_WORK:
                raise AssessmentError("The assessment is too large. Use a smaller inventory or advisory set.")
            score = _rating(affected.get("severity", advisory.get("severity")))
            for component in components.values():
                outcome = _version_match(versions, ranges, reasons, component)
                candidates[component].append((outcome, score, ecosystem))
        for component, entries in candidates.items():
            covered_packages.add(component)
            reasons = sorted({reason for outcome, _, _ in entries for reason in outcome.gaps})
            if reasons:
                gap_count += 1
                if len(gaps) < _MAX_DETAILS:
                    gaps.append({
                        "advisory_id": identifier, "package": component.package.name,
                        "ecosystem": entries[0][2], "version": component.version,
                        "reason": _display(" ".join(reasons), 700),
                    })
            positives = [(outcome, score, ecosystem) for outcome, score, ecosystem in entries if outcome.evidence]
            if not positives:
                continue
            best, _, ecosystem = next(
                (entry for entry in positives if entry[0].confidence == "exact_version"),
                positives[0],
            )
            if len(entries) > 1:
                best = _Outcome(best.evidence, best.confidence, None, best.gaps)
            score = max((score for _, score, _ in positives if score is not None), default=None)
            matched_packages.add(component)
            findings.append(_result(identifier, advisory, aliases, component, ecosystem, best, score, known_exploited))
    findings.sort(key=lambda row: (
        not row["known_exploited"], _SEVERITY_ORDER[row["severity"]],
        row["advisory_id"], row["package"], row["version"],
    ))
    severity_counts = Counter(row["severity"] for row in findings)
    return {
        "assessed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scope": _SCOPE,
        "inventory": inventory,
        "advisories": {
            "records": records_count,
            "input_records": len(raw),
            "withdrawn": withdrawn,
            "invalid_records": discarded,
            "unidentified_affected_entries": unevaluated,
            "severity_unrated_matches": severity_counts["unknown"],
        },
        "summary": {
            "matched_findings": len(findings),
            "matched_packages": len(matched_packages),
            "packages_with_advisory_entries": len(covered_packages),
            "packages_without_advisory_entries": inventory["identified_packages"] - len(covered_packages),
            "known_exploited_findings": sum(row["known_exploited"] for row in findings),
            "coverage_gaps": gap_count,
            "omitted_findings": max(0, len(findings) - _MAX_DETAILS),
            "omitted_coverage_gaps": max(0, gap_count - _MAX_DETAILS),
            "by_severity": {level: severity_counts[level] for level in _SEVERITY_ORDER},
        },
        "findings": findings[:_MAX_DETAILS],
        "coverage_gaps": gaps,
    }


def _load_document(path, limit):
    descriptor = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AssessmentError("Assessment inputs must be regular local files.")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = handle.read(limit + 1)
    except OSError as exc:
        if path.is_dir():
            raise AssessmentError("Assessment inputs must be regular local files.") from exc
        raise AssessmentError(f"Could not read assessment input {_display(path.name, 160)}.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > limit:
        raise AssessmentError(f"Assessment input exceeds its byte limit: {_display(path.name, 160)}.")
    try:
        return json.loads(data), len(data)
    except (ValueError, RecursionError) as exc:
        raise AssessmentError(f"Assessment input is not valid JSON: {_display(path.name, 160)}.") from exc


def assess(
    sbom_path: Path, advisories_paths: Sequence[Path] | Path, *, exploited_ids: Collection[str] = (),
) -> dict:
    """Load bounded local files, then match the inventory against their OSV records."""
    paths = [advisories_paths] if isinstance(advisories_paths, (Path, str)) else list(advisories_paths)
    if not 1 <= len(paths) <= _MAX_FILES:
        raise AssessmentError(f"Select between 1 and {_MAX_FILES} advisory files.")
    inventory, size = _load_document(Path(sbom_path), _MAX_FILE_BYTES)
    advisories = []
    for path in paths:
        data, current_size = _load_document(Path(path), min(_MAX_FILE_BYTES, _MAX_TOTAL_BYTES - size))
        size += current_size
        advisories.extend(_record_list(data))
        if len(advisories) > _MAX_RECORDS:
            raise AssessmentError(f"The assessment supports at most {_MAX_RECORDS:,} advisory records.")
    return assess_documents(inventory, advisories, exploited_ids=exploited_ids)
