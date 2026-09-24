"""WinRM/WMI tests run against a stubbed pywinrm Session.

These verify script construction, quoting, and result parsing. They do NOT
prove interoperability with a real Windows host; see docs/VERIFICATION.md.
"""

import json
from types import SimpleNamespace

import pytest

from watchpost.checks import build_check
from watchpost.checks.base import Result
from watchpost.checks.windows import ps_quote

from .conftest import make_config


class FakeSession:
    scripts: list[str] = []
    reply = (0, "", "")

    def __init__(self, target, auth, **kw):
        FakeSession.target, FakeSession.kw = target, kw

    def run_ps(self, script):
        FakeSession.scripts.append(script)
        rc, out, err = FakeSession.reply
        return SimpleNamespace(status_code=rc, std_out=out.encode(), std_err=err.encode())


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    FakeSession.scripts = []
    monkeypatch.setattr("watchpost.checks.windows.winrm.Session", FakeSession)
    return FakeSession


def check(**kw):
    mon = {"name": "w", "host": "srv01.lab.example", "credential": "win", **kw}
    cfg = make_config([mon])
    return build_check(cfg.monitors[0], cfg)


def test_ps_quote_neutralises_breakout():
    assert ps_quote("a'; Remove-Item C:\\ -Recurse; '") == "'a''; Remove-Item C:\\ -Recurse; '''"


async def test_service_running(fake):
    fake.reply = (0, "Running|Automatic", "")
    res = await check(type="winrm", mode="service", service="W32Time").run()
    assert res.result is Result.OK
    assert "-Name 'W32Time'" in fake.scripts[0]
    assert fake.target == "https://srv01.lab.example:5986/wsman"
    assert fake.kw["server_cert_validation"] == "validate"


async def test_service_stopped(fake):
    fake.reply = (0, "Stopped|Automatic", "")
    res = await check(type="winrm", mode="service", service="Spooler").run()
    assert res.result is Result.FAIL and "Stopped" in res.message


async def test_service_name_is_quoted(fake):
    fake.reply = (0, "Running|Manual", "")
    await check(type="winrm", mode="service", service="x'; whoami; '").run()
    assert "-Name 'x''; whoami; '''" in fake.scripts[0]


async def test_cpu_threshold(fake):
    fake.reply = (0, "91", "")
    res = await check(type="winrm", mode="cpu",
                      thresholds={"direction": "above", "warn": 80, "crit": 95}).run()
    assert res.result is Result.WARN and res.value == 91


async def test_nonzero_exit_reports_stderr(fake):
    fake.reply = (1, "", "Access is denied.\nmore")
    res = await check(type="winrm", mode="memory").run()
    assert res.result is Result.FAIL and "Access is denied." in res.message


async def test_wmi_aggregate(fake):
    fake.reply = (0, json.dumps([10, 20, 30]), "")
    res = await check(type="wmi", query="SELECT * FROM Win32_PerfFormattedData_PerfOS_Processor",
                      property="PercentProcessorTime", aggregate="max").run()
    assert res.result is Result.OK and res.value == 30
    assert "-Query 'SELECT * FROM Win32_PerfFormattedData_PerfOS_Processor'" in fake.scripts[0]


async def test_wmi_single_row_and_count(fake):
    fake.reply = (0, "42", "")
    res = await check(type="wmi", query="SELECT * FROM Win32_Service WHERE State='Stopped'",
                      property="Name", aggregate="count").run()
    assert res.value == 1.0
    assert "State=''Stopped''" in fake.scripts[0]


async def test_certificate_transport_passes_pem_paths(fake):
    cfg = make_config(
        [{"name": "w", "type": "winrm", "host": "h", "credential": "wincert",
          "mode": "service", "service": "WinRM"}],
        credentials={"wincert": {"type": "winrm", "transport": "certificate",
                                 "cert_pem": "/run/secrets/c.pem",
                                 "cert_key_pem": "/run/secrets/k.pem"}},
    )
    fake.reply = (0, "Running|Automatic", "")
    await build_check(cfg.monitors[0], cfg).run()
    assert fake.kw["transport"] == "certificate"
    assert fake.kw["cert_pem"] == "/run/secrets/c.pem"
