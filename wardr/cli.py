"""Wardr's desktop launcher and server-friendly commands."""

import argparse
import io
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from . import (
    assessment, checks, exposure, feedback_loop, feeds, fim, fleet, fleet_agent, hunting, intel, inventory,
    local_ai, remediation, reporting, service, surface, threat_network, updater,
)
from .monitor import Monitor
from .plan import build_plan, html_plan, prioritize_software, text_plan
from .release import ReleaseError, verify_release
from .report import html_report, json_report, report_data, text_report
from .server import RESTART_DASHBOARD, serve
from .state import WardrState, default_state_dir, host_info, prepare_state_dir, read_software, save_local_json
from .update_session import installation_lock


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
    network.add_argument("--offline", action="store_true", help="Disable public advisory and Wardr update downloads.")

    scan = commands.add_parser("scan", help="Run local checks and write a report to stdout.")
    scan.add_argument("--format", choices=("text", "json", "html"), default="text")
    watch = commands.add_parser("watch", help="Monitor locally and emit each new event as one JSON line.")
    watch.add_argument("--interval", type=lambda value: _integer(value, 5, 3600), default=30,
                       help="Seconds between event polls. Default 30.")
    advisories = commands.add_parser("advisories", help="Read the local CISA catalog summary.")
    advisories.add_argument("--refresh", action="store_true", help="Download the public CISA catalog.")
    commands.add_parser("exposure", help="Read local TCP listeners and UDP bindings as JSON.")
    inv = commands.add_parser("inventory", help="Collect an incremental local software inventory (CycloneDX) and AI surface checks.")
    inv.add_argument("--format", choices=("summary", "cyclonedx"), default="summary")
    inv.add_argument("--force", action="store_true", help="Bypass the incremental cache and rescan installed packages.")

    software = commands.add_parser("assess", help="Match a local or auto-discovered CycloneDX inventory to OSV and signed feed advisories.")
    sbom_source = software.add_mutually_exclusive_group(required=True)
    sbom_source.add_argument("--sbom", type=Path, help="A CycloneDX JSON file.")
    sbom_source.add_argument("--auto", action="store_true", help="Automatically discover installed local software.")
    software.add_argument("--advisories", type=Path, nargs="+", default=None, help="One or more local OSV JSON files.")

    feed_cmd = commands.add_parser("feed", help="Inspect, verify, sign, import, or refresh Ed25519-signed Rapid-Defense Feeds.")
    feed_cmd.add_argument("--refresh", action="store_true", help="Download and verify the latest signed defense feed.")
    feed_cmd.add_argument("--import-bundle", type=Path, help="Verify and install a local signed feed bundle.")
    feed_cmd.add_argument("--signature", type=Path, help="Detached Ed25519 signature file for --import-bundle or --sign.")
    feed_cmd.add_argument("--public-key", type=Path, help="Optional trusted Ed25519 PEM public key.")
    feed_cmd.add_argument("--sign", type=Path, help="Validate and Ed25519-sign a declarative Rapid-Defense Feed bundle.")
    feed_cmd.add_argument("--signing-key", type=Path, help="Ed25519 private key PEM file for --sign.")

    fim_cmd = commands.add_parser("fim", help="Initialize or verify SHA-256 integrity of critical security config files.")
    fim_cmd.add_argument("--init", action="store_true", help="Capture and save a fresh integrity baseline.")

    surface_cmd = commands.add_parser("surface", help="Run a non-destructive local attack-surface and loopback TLS hygiene audit.")
    surface_cmd.add_argument("--no-tls-probe", action="store_true", help="Skip loopback TLS certificate checks.")

    svc_cmd = commands.add_parser("service-template", help="Generate a hardened continuous monitoring or fleet-agent service template.")
    svc_cmd.add_argument("--platform", choices=("systemd", "launchd", "windows"), required=True)
    svc_cmd.add_argument("--interval", type=lambda value: _integer(value, 5, 3600), default=30)
    svc_cmd.add_argument("--fleet", action="store_true", help="Generate a service unit for `wardr fleet agent` instead of `wardr watch`.")

    fleet_cmd = commands.add_parser("fleet", help="Manage or join a self-hosted Wardr Fleet for servers and user computers.")
    fleet_sub = fleet_cmd.add_subparsers(dest="fleet_action", required=True)
    fl_srv = fleet_sub.add_parser("server", help="Start the Wardr Fleet control plane and web console.")
    fl_srv.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1).")
    fl_srv.add_argument("--port", type=lambda value: _integer(value, 0, 65535), default=8443)
    fl_srv.add_argument("--admin-user", default="admin", help="Initial bootstrap administrator username.")
    fl_srv.add_argument("--admin-password", default=None, help="Initial bootstrap administrator password (auto-generated if omitted).")
    fl_enr = fleet_sub.add_parser("enroll", help="Enroll this machine into a Wardr Fleet control plane.")
    fl_enr.add_argument("--server", required=True, help="Wardr Fleet server URL (HTTPS for remote servers).")
    fl_enr.add_argument("--token", required=True, help="Short-lived enrollment token minted by a Fleet admin.")
    fl_enr.add_argument("--role", choices=("server", "workstation"), default=None)
    fl_enr.add_argument("--tags", default="", help="Comma-separated tags (for example prod,linux,us-east).")
    fleet_sub.add_parser("checkin", help="Perform one fleet heartbeat and execute any queued allowlisted actions.")
    fl_agt = fleet_sub.add_parser("agent", help="Run the continuous low-overhead Wardr Fleet check-in agent.")
    fl_agt.add_argument("--interval", type=lambda value: _integer(value, 10, 3600), default=60)
    fleet_sub.add_parser("status", help="Show this host's local Wardr Fleet enrollment status.")

    tn_cmd = commands.add_parser("threat-network", help="Run the self-hostable central intake, zero-day clustering, and signed feed server.")
    tn_cmd.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1).")
    tn_cmd.add_argument("--port", type=lambda value: _integer(value, 0, 65535), default=8787)
    tn_cmd.add_argument("--signing-key", type=Path, help="Optional Ed25519 private key PEM file for /v1/feeds/publish.")
    tn_cmd.add_argument("--admin-token", default=None, help="Optional operator Bearer token (generated automatically if omitted).")

    fl_cmd = commands.add_parser("feedback-loop", help="Pull live Threat Network telemetry & clusters and drive reviewed releases.")
    fl_sub = fl_cmd.add_subparsers(dest="feedback_action", required=True)
    fl_dig = fl_sub.add_parser("digest", help="Fetch live telemetry & zero-day clusters and build a release triage digest.")
    fl_dig.add_argument("--server", default=feedback_loop.DEFAULT_API_URL, help="Wardr Threat Network API URL.")
    fl_dig.add_argument("--token-env", default="WARDR_ADMIN_TOKEN", help="Environment variable holding the admin Bearer token.")
    fl_dig.add_argument("--format", choices=("markdown", "json"), default="markdown")
    fl_dig.add_argument("--out-dir", type=Path, default=None, help="Optional directory to write digest.md, digest.json, and defense-v1.draft.json.")
    fl_dig.add_argument("--fail-on-escalated", action="store_true", help="Exit with status 2 if escalated zero-day clusters exist.")

    fl_prep = fl_sub.add_parser("prepare-release", help="Bump pyproject.toml, changelog.py, and index.html for the next release.")
    fl_prep.add_argument("--repo", type=Path, default=Path("."), help="Wardr repository root (default current directory).")
    fl_prep.add_argument("--version", default=None, help="Explicit X.Y.Z target version (overrides --bump).")
    fl_prep.add_argument("--bump", choices=("patch", "minor", "major"), default="patch")
    fl_prep.add_argument("--title", default="", help="Custom release title for What's New.")
    fl_prep.add_argument("--summary", default="", help="Custom release summary for What's New.")
    fl_prep.add_argument("--from-live", action="store_true", help="Pull live telemetry from --server to pre-populate changelog highlights.")
    fl_prep.add_argument("--server", default=feedback_loop.DEFAULT_API_URL, help="Wardr Threat Network API URL (for --from-live).")
    fl_prep.add_argument("--token-env", default="WARDR_ADMIN_TOKEN", help="Environment variable holding the admin Bearer token.")
    fl_prep.add_argument("--dry-run", action="store_true", help="Validate and preview the bump without writing files.")

    fl_pub = fl_sub.add_parser("publish-release", help="Run tests, verify git state, push main, and invoke packaging/release.py.")
    fl_pub.add_argument("--repo", type=Path, default=Path("."), help="Wardr repository root (default current directory).")
    fl_pub.add_argument("--version", required=True, help="Release version X.Y.Z matching pyproject.toml.")
    fl_pub.add_argument("--site", type=Path, default=Path("../Wardr-Site"), help="Local Wardr-Site checkout path.")
    fl_pub.add_argument("--signing-repo", type=Path, default=Path("../resonant-client"), help="Local signing repository checkout path.")
    fl_pub.add_argument("--signing-key", type=Path, default=Path("~/.config/wardr-release/community-ed25519.pem"),
                        help="Local Ed25519 private signing key PEM path.")
    fl_pub.add_argument("--plan", action="store_true", help="Preview the release pipeline without pushing or publishing.")

    fix_cmd = commands.add_parser("fix", help="Preview, apply, or roll back allowlisted local security remediations.")
    fix_action = fix_cmd.add_mutually_exclusive_group(required=True)
    fix_action.add_argument("--preview", metavar="CHECK_ID", help="Show exact changes before applying a fix.")
    fix_action.add_argument("--apply", metavar="CHECK_ID", help="Apply an allowlisted fix and record a rollback snapshot.")
    fix_action.add_argument("--undo", metavar="ROLLBACK_ID", help="Restore prior permissions from a remediation rollback ID.")
    fix_action.add_argument("--history", action="store_true", help="Show recent remediation history and rollback IDs.")

    report_cmd = commands.add_parser("report-issue", help="Build, export, or submit a strictly redacted vulnerability/zero-day report.")
    report_target = report_cmd.add_mutually_exclusive_group(required=True)
    report_target.add_argument("--finding", metavar="CHECK_ID", help="Build a redacted report from a check ID in the latest scan.")
    report_target.add_argument("--alert", metavar="ALERT_ID", help="Build a redacted report from a hunting alert ID.")
    report_target.add_argument("--custom", metavar="TITLE", help="Build a redacted custom vulnerability/zero-day report.")
    report_cmd.add_argument("--notes", default="", help="Optional operator notes (also automatically redacted).")
    report_cmd.add_argument("--zero-day", action="store_true", help="Flag this report as a suspected zero-day / novel vulnerability.")
    report_cmd.add_argument("--out", type=Path, help="Export the redacted JSON report to a local file.")
    report_cmd.add_argument("--submit", action="store_true", help="Submit the redacted report over HTTPS to Wardr central intake.")
    plan = commands.add_parser("plan", help="Build a prioritized plan from local checks, telemetry, and saved software matches.")
    plan.add_argument("--format", choices=("text", "json", "html"), default="text")
    model = commands.add_parser("model", help="Prepare or use the optional local model.")
    model.add_argument("action", choices=("status", "pull", "review"))
    integrity = commands.add_parser("verify-release", help="Verify a downloaded release with a trusted Ed25519 key.")
    integrity.add_argument("--manifest", required=True, type=Path)
    integrity.add_argument("--signature", required=True, type=Path)
    integrity.add_argument("--public-key", required=True, type=Path)
    integrity.add_argument("artifact", type=Path)
    update = commands.add_parser("update", help="Check or install a signed Wardr update in this environment.")
    update.add_argument("--check", action="store_true", help="Check for an update without installing it.")
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
    local_exposure = exposure.collect_exposure()
    events = hunting.analyze(Monitor(state_dir=directory).poll(), feed_rules=feeds.load_feed_rules(directory))
    software = prioritize_software(
        read_software(directory / "software-assessment.json"), intel.advisory_status(directory),
    )
    return build_plan(host_info(), scan, local_exposure, events, software)


def _relaunch_dashboard(arguments: list[str]) -> int:
    executable = os.path.abspath(sys.executable)
    command = [executable, "-I", "-m", "wardr", *arguments]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "nt":
        subprocess.Popen(command)
        return 0
    os.execv(executable, command)


def _serve_dashboard(directory: Path, args, arguments: list[str], windows_launcher: bool) -> int:
    explicit = args.command == "serve"
    open_browser = not explicit or not args.no_browser
    if windows_launcher and open_browser and not (explicit and args.offline) and not updater.installation_problem():
        # Windows locks an active console launcher. Run the desktop in the Python
        # interpreter so a later update can replace its original launcher.
        return _relaunch_dashboard(arguments)
    state = WardrState(directory, args.interval if explicit else 30, offline=explicit and args.offline)
    update_blocker = (
        "Windows keeps wardr.exe open here. Start Wardr with the environment’s Python using -m wardr serve."
        if windows_launcher else None
    )
    outcome = serve(state, args.port if explicit else 0, open_browser, explicit and args.auto_advisories,
                    update_blocker=update_blocker)
    if outcome is RESTART_DASHBOARD:
        return _relaunch_dashboard(arguments)
    return 0


def _update_cli(check_only: bool) -> int:
    if problem := updater.installation_problem():
        raise updater.UpdaterError(problem)
    with installation_lock():
        available = updater.check_for_update()
        if available:
            if check_only:
                print(f"Wardr {available.version} is available. Open Updates in Wardr to install it.")
            else:
                version = updater.install_update(available)
                print(f"Installed Wardr {version}. Restart any running Wardr dashboard.")
        else:
            print("Your Wardr installation is up to date.")
    return 0


def main(argv: list[str] | None = None) -> int:
    if sys.platform == "win32" and isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    parser = _parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(arguments)
    windows_launcher = argv is None and os.name == "nt" and Path(sys.argv[0]).name.lower() == "wardr.exe"
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
        elif args.command == "inventory":
            collected = inventory.collect_inventory(directory, force=args.force)
            if args.format == "cyclonedx":
                print(json_report(collected["sbom"]), end="")
            else:
                ai_checks = inventory.scan_ai_surface(exposure_result=exposure.collect_exposure())
                summary = {
                    "collected_at": collected["collected_at"],
                    "cached": collected["cached"],
                    "component_count": collected["component_count"],
                    "sources": collected["sources"],
                    "ai_surface_checks": ai_checks,
                }
                print(json_report(summary), end="")
        elif args.command == "assess":
            catalog = intel.advisory_status(directory)
            index, _ = intel.exploited_index(catalog)
            if args.auto:
                collected = inventory.collect_inventory(directory)
                advisories_list = list(feeds.load_feed_advisories(directory))
                if args.advisories:
                    for adv_path in args.advisories:
                        loaded, _ = assessment._load_document(adv_path, assessment._MAX_FILE_BYTES)
                        advisories_list.extend(assessment._record_list(loaded))
                result = assessment.assess_documents(collected["sbom"], advisories_list, exploited_ids=index)
            else:
                if not args.advisories:
                    raise assessment.AssessmentError("Provide --advisories or use --auto with an installed Rapid-Defense Feed.")
                result = assessment.assess(args.sbom, args.advisories, exploited_ids=index)
            save_local_json(directory / "software-assessment.json", result)
            print(json_report(prioritize_software(result, catalog)), end="")
        elif args.command == "feed":
            if args.sign:
                if not args.signing_key or not args.signature:
                    raise feeds.FeedError("Provide --signing-key and --signature with --sign.")
                raw = Path(args.sign).read_bytes()
                sig = feeds.sign_feed_bytes(raw, Path(args.signing_key).read_bytes())
                Path(args.signature).write_bytes(sig)
                result = {"signed": True, "bundle": str(args.sign), "signature": str(args.signature), "bytes": len(raw)}
            elif args.import_bundle:
                if not args.signature:
                    raise feeds.FeedError("Provide --signature with --import-bundle.")
                result = feeds.import_feed(directory, args.import_bundle, args.signature, args.public_key)
            elif args.refresh:
                result = feeds.refresh_feed(directory)
            else:
                result = feeds.feed_status(directory)
            print(json_report(result), end="")
        elif args.command == "fim":
            result = fim.init_baseline(directory) if args.init else fim.check_integrity(directory)
            print(json_report(result), end="")
        elif args.command == "surface":
            result = surface.audit_exposure(exposure.collect_exposure(), probe_local_tls=not args.no_tls_probe)
            print(json_report(result), end="")
        elif args.command == "service-template":
            print(
                service.render_template(
                    args.platform,
                    state_dir=str(args.state_dir) if args.state_dir else "",
                    interval=args.interval,
                    fleet=args.fleet,
                ),
                end="",
            )
        elif args.command == "fleet":
            if args.fleet_action == "server":
                store = fleet.FleetStore(directory / "fleet")
                created = store.ensure_bootstrap_admin(args.admin_user, args.admin_password)
                with fleet.FleetServer((args.host, args.port), store) as srv:
                    print(f"Wardr Fleet console running at http://{args.host}:{srv.server_port}", flush=True)
                    if created:
                        print(f"Bootstrap admin credentials -> username: {created[0]}  password: {created[1]}", flush=True)
                    try:
                        srv.serve_forever()
                    except KeyboardInterrupt:
                        pass
            elif args.fleet_action == "enroll":
                print(json_report(fleet_agent.enroll(
                    directory, args.server, args.token, role=args.role, tags=args.tags,
                )), end="")
            elif args.fleet_action == "checkin":
                print(json_report(fleet_agent.checkin_once(directory)), end="")
            elif args.fleet_action == "agent":
                fleet_agent.run_agent(directory, interval=args.interval)
            elif args.fleet_action == "status":
                print(json_report(fleet_agent.agent_status(directory)), end="")
        elif args.command == "threat-network":
            store = threat_network.ThreatNetworkStore(directory / "threat-network")
            key_bytes = Path(args.signing_key).read_bytes() if args.signing_key else None
            with threat_network.ThreatNetworkServer(
                (args.host, args.port), store, admin_token=args.admin_token, signing_key_pem=key_bytes,
            ) as srv:
                print(f"Wardr Threat Network listening on http://{args.host}:{srv.server_port}", flush=True)
                if args.admin_token is None:
                    print(f"Operator Bearer token: {srv.admin_token}", flush=True)
                try:
                    srv.serve_forever()
                except KeyboardInterrupt:
                    pass
        elif args.command == "feedback-loop":
            if args.feedback_action == "digest":
                token = os.environ.get(args.token_env, "")
                signals = feedback_loop.fetch_live_signals(args.server, admin_token=token)
                digest = feedback_loop.build_triage_digest(signals)
                if args.out_dir:
                    feedback_loop.write_digest_artifacts(digest, args.out_dir)
                if args.format == "json":
                    print(json_report({k: v for k, v in digest.items() if k != "markdown"}), end="")
                else:
                    print(digest["markdown"], end="")
                if args.fail_on_escalated and digest["escalated_count"] > 0:
                    return 2
            elif args.feedback_action == "prepare-release":
                highlights = None
                if args.from_live:
                    token = os.environ.get(args.token_env, "")
                    signals = feedback_loop.fetch_live_signals(args.server, admin_token=token)
                    digest = feedback_loop.build_triage_digest(signals)
                    highlights = digest["recommended_highlights"]
                result = feedback_loop.prepare_release_bump(
                    args.repo,
                    target_version=args.version,
                    bump=args.bump,
                    title=args.title,
                    summary=args.summary,
                    highlights=highlights,
                    dry_run=args.dry_run,
                )
                print(json_report(result), end="")
            elif args.feedback_action == "publish-release":
                repo = args.repo.expanduser().resolve()
                release_script = repo / "packaging" / "release.py"
                if not release_script.is_file():
                    raise feedback_loop.FeedbackLoopError(f"Could not find release runner at {release_script}.")
                # 1. Run full unit test suite before touching git/release
                test_run = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"], cwd=repo)
                if test_run.returncode != 0:
                    raise feedback_loop.FeedbackLoopError("Unit tests failed. Fix failing tests before publishing.")
                if not args.plan:
                    dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"], text=True).strip()
                    if dirty:
                        raise feedback_loop.FeedbackLoopError(
                            "Repository has uncommitted changes. Review and commit your release changes first."
                        )
                    push_run = subprocess.run(["git", "-C", str(repo), "push", "origin", "main"])
                    if push_run.returncode != 0:
                        raise feedback_loop.FeedbackLoopError("Failed to push main to origin before release.")
                cmd = [
                    sys.executable, str(release_script),
                    "--version", args.version,
                    "--site", str(args.site.expanduser().resolve()),
                    "--signing-repo", str(args.signing_repo.expanduser().resolve()),
                    "--signing-key", str(args.signing_key.expanduser().resolve()),
                ]
                if args.plan:
                    cmd.append("--plan")
                rel_run = subprocess.run(cmd, cwd=repo)
                return rel_run.returncode
        elif args.command == "fix":
            if args.preview:
                print(json_report(remediation.preview_fix(args.preview)), end="")
            elif args.apply:
                print(json_report(remediation.apply_fix(args.apply, state_dir=directory)), end="")
            elif args.undo:
                print(json_report(remediation.undo_fix(args.undo, directory)), end="")
            else:
                print(json_report({"history": remediation.list_history(directory)}), end="")
        elif args.command == "report-issue":
            state = WardrState(directory, offline=not args.submit)
            if args.finding:
                built = state.preview_report("finding", args.finding, notes=args.notes, suspected_zero_day=args.zero_day)
            elif args.alert:
                built = state.preview_report("alert", args.alert, notes=args.notes, suspected_zero_day=args.zero_day)
            else:
                built = state.preview_report("custom", args.custom, notes=args.notes, suspected_zero_day=args.zero_day)
            if args.out:
                out_info = reporting.export_report(built["payload"], args.out)
                print(json_report({**built, **out_info}), end="")
            elif args.submit:
                sub_info = reporting.submit_report(built["payload"], state_dir=directory, offline=False)
                print(json_report({**built, **sub_info}), end="")
            else:
                print(json_report(built), end="")
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
        elif args.command == "update":
            if windows_launcher and not args.check:
                raise updater.UpdaterError(f'Use the Updates button or run "{sys.executable}" -m wardr update.')
            return _update_cli(args.check)
        else:
            return _serve_dashboard(directory, args, arguments, windows_launcher)
    except KeyboardInterrupt:
        return 0
    except (
        OSError, ValueError, assessment.AssessmentError, feedback_loop.FeedbackLoopError, feeds.FeedError,
        fleet_agent.FleetAgentError, intel.AdvisoryError, local_ai.LocalAIError, ReleaseError,
        reporting.ReportingError, updater.UpdaterError,
    ) as exc:
        print(f"Wardr: {exc}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous_term)
    return 0
