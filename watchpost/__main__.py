"""Entry point.

  python -m watchpost --config /config/watchpost.yaml          run the service
  python -m watchpost --config ... --validate                  check config and exit
  python -m watchpost --config ... --once [--only SLUG]        poll once, print, exit
  python -m watchpost --config ... --discover [--target 192.0.2.0/24 ...]
        [--credential NAME ...] [--out proposals.yaml] [--report report.json]
                                                               propose monitors, exit
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys

import uvicorn

from . import __version__
from .alerts import Alerter
from .config import ConfigError, load_config
from .scheduler import Scheduler
from .store import Store
from .web import create_app

log = logging.getLogger("watchpost")


async def _once(config, only: str | None) -> int:  # type: ignore[no-untyped-def]
    store = Store(":memory:")
    sched = Scheduler(config, store, Alerter(config))
    monitors = [m for m in sched.monitors if only in (None, m.slug)]
    if not monitors:
        print(f"no enabled monitor matches {only!r}", file=sys.stderr)
        return 2
    results = await asyncio.gather(*(sched.poll_once(m) for m in monitors))
    worst = 0
    for mon, res in zip(monitors, results):
        print(f"{res.result.value.upper():5} {mon.slug:32} {res.message}")
        worst = max(worst, {"ok": 0, "warn": 1, "fail": 2}[res.result.value])
    return worst


async def _serve(config) -> None:  # type: ignore[no-untyped-def]
    store = Store(config.server.db_path)
    alerter = Alerter(config)
    sched = Scheduler(config, store, alerter)
    app = create_app(config, store, sched, alerter)
    server = uvicorn.Server(uvicorn.Config(
        app, host=config.server.listen, port=config.server.port,
        log_level="warning", access_log=False, proxy_headers=False,
    ))
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: setattr(server, "should_exit", True))
    sched.start()
    log.info("watchpost %s: %d monitors, %d alert targets, listening on %s:%d",
             __version__, len(sched.monitors), len(config.alerts),
             config.server.listen, config.server.port)
    try:
        await server.serve()
    finally:
        await sched.stop()
        store.close()


def _discover(config, args) -> int:  # type: ignore[no-untyped-def]
    import json
    from pathlib import Path

    from .discovery import DiscoveryError, discover

    try:
        text, report = asyncio.run(discover(config, args.target, args.credential,
                                            use_directory=not args.no_directory))
    except (DiscoveryError, ValueError) as err:
        print(f"discovery error: {err}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if args.report:
        Path(args.report).write_text(json.dumps(report, indent=2, default=str),
                                     encoding="utf-8")
    if args.known_hosts_out and report["new_ssh_host_keys"]:
        Path(args.known_hosts_out).write_text("\n".join(report["new_ssh_host_keys"]) + "\n",
                                              encoding="utf-8")
    if args.certs_out and report["unverified_certs"]:
        out_dir = Path(args.certs_out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for ep, c in report["unverified_certs"].items():
            (out_dir / (ep.replace(":", "_") + ".pem")).write_text(c["pem"], encoding="utf-8")
    st = report["stats"]
    print(f"scanned {st['scanned']}, responded {st['responded']}, proposed {st['proposed']}, "
          f"skipped {st['skipped']} already configured", file=sys.stderr)
    if report["new_ssh_host_keys"]:
        print(f"{len(report['new_ssh_host_keys'])} SSH host keys seen for the first time; "
              "verify before trusting (listed at the end of the proposals)", file=sys.stderr)
    if report["directory"]["skipped"]:
        print(f"directory: {len(report['directory']['skipped'])} accounts skipped "
              "(disabled, stale, or filtered; see --report)", file=sys.stderr)
    if st["retired_credentials"]:
        print("credentials retired after repeated auth failures: "
              + ", ".join(st["retired_credentials"]), file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="watchpost")
    ap.add_argument("--config", default="/config/watchpost.yaml")
    ap.add_argument("--validate", action="store_true", help="validate config and exit")
    ap.add_argument("--once", action="store_true", help="poll every monitor once and exit")
    ap.add_argument("--only", help="with --once, poll only this monitor slug")
    ap.add_argument("--discover", action="store_true",
                    help="scan targets and write proposed monitors; changes nothing")
    ap.add_argument("--target", action="append",
                    help="with --discover: CIDR, a-b range, IP, or hostname (repeatable; "
                         "overrides discovery.targets)")
    ap.add_argument("--credential", action="append",
                    help="with --discover: credential name to try (repeatable; overrides "
                         "discovery.credentials)")
    ap.add_argument("--out", help="with --discover: write proposals here instead of stdout")
    ap.add_argument("--report", help="with --discover: also write a JSON findings report")
    ap.add_argument("--known-hosts-out",
                    help="with --discover: write first-seen SSH host keys here for review")
    ap.add_argument("--certs-out",
                    help="with --discover: directory to save certificates that did not "
                         "validate, one PEM per endpoint, for review and pinning")
    ap.add_argument("--no-directory", action="store_true",
                    help="with --discover: do not query discovery.directory")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args()
    logging.basicConfig(level=args.log_level.upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per HTTP probe is noise
    try:
        config = load_config(args.config)
    except ConfigError as err:
        print(f"config error: {err}", file=sys.stderr)
        return 2
    if args.validate:
        print(f"ok: {len(config.monitors)} monitors, {len(config.credentials)} credentials, "
              f"{len(config.alerts)} alert targets")
        return 0
    if args.once:
        return asyncio.run(_once(config, args.only))
    if args.discover:
        return _discover(config, args)
    asyncio.run(_serve(config))
    return 0


if __name__ == "__main__":
    sys.exit(main())
