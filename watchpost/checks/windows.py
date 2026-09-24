"""Windows checks over WinRM (WS-Management).

Both the `winrm` and `wmi` monitor types travel over WinRM. The `wmi` type
runs a WQL query through Get-CimInstance, which is the same CIM repository
classic WMI reads, carried over WS-Man (5985/5986) instead of DCOM/RPC
(135 plus the dynamic 49152-65535 range). That is a deliberate choice for a
segmented network: one well-known, TLS-capable port instead of an RPC range,
and no dependence on DCOM hardening changes. Native DCOM WMI is not
implemented.

pywinrm is synchronous, so each probe runs in a worker thread.

Everything interpolated into PowerShell is placed inside single-quoted
string literals with embedded single quotes doubled, so a service name or
WQL text from the config can not break out into script context.
"""

from __future__ import annotations

import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import winrm
from winrm.exceptions import WinRMError, WinRMTransportError

from .base import Check, CheckResult, Result

try:  # requests is a pywinrm dependency
    from requests.exceptions import RequestException
except ImportError:  # pragma: no cover
    RequestException = OSError  # type: ignore[misc,assignment]


# A dedicated pool: WinRM calls take seconds, and on the default pool
# (CPU count + 4 threads, 8 on a Pi 5) they would queue behind each other and
# starve the SQLite writes that share it.
WINRM_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="winrm")


def ps_quote(value: str) -> str:
    """Return a PowerShell single-quoted literal for value."""
    return "'" + value.replace("'", "''") + "'"


class _WsManCheck(Check):
    def _session(self) -> winrm.Session:
        m = self.monitor
        cred = self.credential()
        scheme = "https" if m.https else "http"
        kwargs: dict[str, Any] = {
            "transport": cred.transport,
            "server_cert_validation": "validate" if m.verify_tls else "ignore",
            "read_timeout_sec": int(self.timeout) + 10,
            "operation_timeout_sec": max(int(self.timeout), 1) + 5,
        }
        if m.ca_bundle:
            kwargs["ca_trust_path"] = m.ca_bundle
        if cred.transport == "certificate":
            kwargs["cert_pem"] = cred.cert_pem
            kwargs["cert_key_pem"] = cred.cert_key_pem
        auth = (cred.username or "", cred.password or "")
        return winrm.Session(f"{scheme}://{m.host}:{m.port}/wsman", auth=auth, **kwargs)

    def _run_ps_sync(self, script: str) -> tuple[int, str, str]:
        r = self._session().run_ps(script)
        return (r.status_code, r.std_out.decode(errors="replace").strip(),
                r.std_err.decode(errors="replace").strip())

    async def run_ps(self, script: str) -> tuple[int, str, str]:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(WINRM_POOL, self._run_ps_sync, script), self.timeout + 30
        )

    async def probe(self) -> CheckResult:
        try:
            return await self._probe()
        except asyncio.TimeoutError:
            return CheckResult.fail("WinRM call timed out")
        except (WinRMTransportError, WinRMError, RequestException, OSError) as err:
            return CheckResult.fail(f"WinRM: {type(err).__name__}: {err}")

    async def _probe(self) -> CheckResult:  # pragma: no cover - abstract
        raise NotImplementedError

    @staticmethod
    def _number(out: str) -> float | None:
        try:
            return float(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None


class WinRMCheck(_WsManCheck):
    async def _probe(self) -> CheckResult:
        m = self.monitor
        if m.mode == "service":
            script = (f"$s = Get-Service -Name {ps_quote(m.service)} -ErrorAction Stop; "
                      "$s.Status.ToString() + '|' + $s.StartType.ToString()")
            rc, out, err = await self.run_ps(script)
            if rc != 0:
                return CheckResult.fail(f"service query failed: {err.splitlines()[0] if err else rc}")
            status, _, start = out.partition("|")
            if status != "Running":
                return CheckResult.fail(f"{m.service} is {status} (StartType {start})")
            return CheckResult.ok(f"{m.service} is Running", detail={"start_type": start})

        scripts = {
            "cpu": "(Get-CimInstance Win32_Processor | Measure-Object -Property "
                   "LoadPercentage -Average).Average",
            "memory": "$o = Get-CimInstance Win32_OperatingSystem; "
                      "[math]::Round((1 - $o.FreePhysicalMemory / $o.TotalVisibleMemorySize) "
                      "* 100, 1)",
            "disk": "$d = Get-CimInstance Win32_LogicalDisk -Filter "
                    + ps_quote(f"DeviceID='{m.disk}'")
                    + "; [math]::Round((1 - $d.FreeSpace / $d.Size) * 100, 1)",
            "powershell": m.script or "",
        }
        rc, out, err = await self.run_ps(scripts[m.mode])
        if rc != 0:
            return CheckResult.fail(f"script failed: {err.splitlines()[0] if err else rc}")
        num = self._number(out)
        if num is None:
            return CheckResult.fail(f"expected a number, got {out[:80]!r}")
        unit = "" if m.mode == "powershell" else "%"
        label = {"cpu": "CPU", "memory": "RAM used", "disk": f"{m.disk} used",
                 "powershell": "result"}[m.mode]
        return CheckResult.ok(f"{label} {num:g}{unit}", value=num, unit=unit)


class WmiCheck(_WsManCheck):
    async def _probe(self) -> CheckResult:
        m = self.monitor
        script = (
            f"$r = @(Get-CimInstance -Namespace {ps_quote(m.namespace)} "
            f"-Query {ps_quote(m.query)} -ErrorAction Stop | "
            f"Select-Object -ExpandProperty {ps_quote(m.property)}); "
            "ConvertTo-Json -Compress -InputObject $r"
        )
        rc, out, err = await self.run_ps(script)
        if rc != 0:
            return CheckResult.fail(f"WQL failed: {err.splitlines()[0] if err else rc}")
        try:
            rows = json.loads(out) if out else []
        except json.JSONDecodeError:
            return CheckResult.fail(f"unparseable result {out[:80]!r}")
        if not isinstance(rows, list):
            rows = [rows]
        if m.aggregate == "count":
            return CheckResult.ok(f"{len(rows)} rows", value=float(len(rows)))
        nums = [float(r) for r in rows if isinstance(r, (int, float))]
        if not nums:
            return CheckResult.fail(f"query returned no numeric {m.property!r} values")
        agg = {"first": nums[0], "sum": sum(nums), "avg": sum(nums) / len(nums),
               "max": max(nums), "min": min(nums)}[m.aggregate]
        res = CheckResult.ok(f"{m.aggregate}({m.property}) = {agg:g} over {len(nums)} rows",
                             value=agg)
        if len(nums) != len(rows):
            res.result = Result.WARN
            res.message += f"; {len(rows) - len(nums)} non-numeric rows ignored"
        return res
