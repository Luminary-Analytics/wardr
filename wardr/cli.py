"""Wardr's desktop launcher and server-friendly commands."""

import argparse
import io
import json
import signal
import sys
import time
from pathlib import Path

from . import assessment, checks, exposure, hunting, intel, local_ai
from .monitor import Monitor
from .plan import build_plan, html_plan, prioritize_software, text_plan
from .release import ReleaseError, verify_release
from .report import html_report, json_report, report_data, text_report
from .server import serve
from .state import WardrState, default_state_dir, host_info, prepare_state_dir, read_software, save_local_json


def _integer(value: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError:
        number = minimum - 1
    if not minimum <= number <= maximum:
        raise argparse.ArgumentTypeError(f"Choose an integer from {minimum} to {maximum}.")
    return number


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wardr", description="Local security posture and event monitoring.")
    parser.add_argument("--state-dir", type=Path, default=None, help="Use a custom local directory for Wardr data.")
    commands = parser.add_subparsers(dest="command")

    dashboard = commands.add_parser("serve", help="Start the local dashboard and event monitor (default).")
    dashboard.add_argument("--port", type=lambda value: _integer(value, 0, 65535), default=0,
                           help="Local port. Zero chooses a free port.")
    dashboard.add_argument("--no-browser", action="store_true", help="Print the URL without opening a browser.")
    dashboard.add_argument("--interval", type=lambda value: _integer(value, 5, 3600), default=30,
                           help="Seconds between event polls. Default 30.")
    network = dashboard.add_mutually_exclusive_group()
    network.add_argument("--auto-advisories", action="store_true",
                         help="Download the public CISA catalog on startup and every six hours.")
    network.add_argument("--offline", action="store_true", help="Disable public advisory downloads.")

    scan = commands.add_parser("scan", help="Run local checks and write a report to stdout.")
    scan.add_argument("--format", choices=("text", "json", "html"), default="text")
    watch = commands.add_parser("watch", help="Monitor locally and emit each new event as one JSON line.")
    watch.add_argument("--interval", type=lambda value: _integer(value, 5, 3600), default=30,
                       help="Seconds between event polls. Default 30.")
    advisories = commands.add_parser("advisories", help="Read the local CISA catalog summary.")
    advisories.add_argument("--refresh", action="store_true", help="Download the public CISA catalog.")
    commands.add_parser("exposure", help="Read local TCP listeners and UDP bindings as JSON.")
    software = commands.add_parser("assess", help="Match a CycloneDX inventory to locally supplied OSV advisories.")
    software.add_argument("--sbom", type=Path, required=True, help="A CycloneDX JSON file.")
    software.add_argument("--advisories", type=Path, nargs="+", required=True, help="One or more OSV JSON files.")
    plan = commands.add_parser("plan", help="Build a prioritized plan from local checks, telemetry, and saved software matches.")
    plan.add_argument("--format", choices=("text", "json", "html"), default="text")
    model = commands.add_parser("model", help="Prepare or use the optional local model.")
    model.add_argument("action", choices=("status", "pull", "review"))
    integrity = commands.add_parser("verify-release", help="Verify a downloaded release with a trusted Ed25519 key.")
    integrity.add_argument("--manifest", required=True, type=Path)
    integrity.add_argument("--signature", required=True, type=Path)
    integrity.add_argument("--public-key", required=True, type=Path)
    integrity.add_argument("artifact", type=Path)
    return parser


def _watch(directory: Path, interval: int) -> None:
    monitor = Monitor(interval=interval, state_dir=directory)
    seen = {item["id"] for item in monitor.status()["events"]}
    previous_coverage = None
    monitor.start()
    try:
        while True:
            status = monitor.status()
            for event in sorted(status["events"], key=lambda item: (item["at"], item["id"])):
                if event["id"] not in seen:
                    print(json.dumps(event, ensure_ascii=True), flush=True)
            seen = {event["id"] for event in status["events"]}
            coverage = status.get("coverage", [])
            if status.get("last_poll") and coverage != previous_coverage:
                print(json.dumps({"coverage": coverage}, ensure_ascii=True), file=sys.stderr, flush=True)
                previous_coverage = coverage
            time.sleep(1)
    finally:
        monitor.stop()


def _interrupt(_signum, _frame) -> None:
    raise KeyboardInterrupt


def _collect_plan(directory: Path) -> dict:
    scan = checks.scan()
    save_local_json(directory / "latest-scan.json", scan)
    inventory = exposure.collect_exposure()
    events = hunting.analyze(Monitor(state_dir=directory).poll())
    software = prioritize_software(
        read_software(directory / "software-assessment.json"), intel.advisory_status(directory),
    )
    return build_plan(host_info(), scan, inventory, events, software)


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32" and isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = _parser()
    args = parser.parse_args(argv)
    directory = args.state_dir.expanduser().resolve() if args.state_dir else default_state_dir()
    previous_term = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, _interrupt)
    try:
        prepare_state_dir(directory)
        if args.command == "scan":
            scan = checks.scan()
            save_local_json(directory / "latest-scan.json", scan)
            render = {"text": text_report, "json": json_report, "html": html_report}[args.format]
            print(render(report_data(host_info(), scan)), end="")
        elif args.command == "watch":
            _watch(directory, args.interval)
        elif args.command == "advisories":
            get_catalog = intel.refresh_advisories if args.refresh else intel.advisory_status
            print(json_report(intel.public_status(get_catalog(directory))), end="")
        elif args.command == "exposure":
            print(json_report(exposure.collect_exposure()), end="")
        elif args.command == "assess":
            catalog = intel.advisory_status(directory)
            index, _ = intel.exploited_index(catalog)
            result = assessment.assess(args.sbom, args.advisories, exploited_ids=index)
            save_local_json(directory / "software-assessment.json", result)
            print(json_report(prioritize_software(result, catalog)), end="")
        elif args.command == "plan":
            render = {"text": text_plan, "json": json_report, "html": html_plan}[args.format]
            print(render(_collect_plan(directory)), end="")
        elif args.command == "model":
            if args.action == "pull":
                result = local_ai.prepare_model()
            elif args.action == "review":
                result = local_ai.review(_collect_plan(directory))
            else:
                result = local_ai.status()
            print(json_report(result), end="")
        elif args.command == "verify-release":
            print(json_report(verify_release(args.manifest, args.signature, args.public_key, args.artifact)), end="")
        elif args.command == "serve":
            return serve(WardrState(directory, args.interval, offline=args.offline),
                         args.port, not args.no_browser, args.auto_advisories)
        else:
            return serve(WardrState(directory), 0, True, False)
    except KeyboardInterrupt:
        return 0
    except (OSError, assessment.AssessmentError, intel.AdvisoryError, local_ai.LocalAIError, ReleaseError) as exc:
        print(f"Wardr: {exc}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    return 0
