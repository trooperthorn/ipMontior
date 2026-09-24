"""Check implementations, keyed by monitor `type`."""

from __future__ import annotations

from typing import Any

from ..config import Config
from .apps import HomeAssistantCheck, TechnitiumCheck, UniFiNetworkCheck, UniFiProtectCheck
from .base import Check, CheckResult, Result
from .mqtt import MqttCheck
from .net import DnsCheck, HttpCheck, PingCheck, TcpCheck, TlsCertCheck
from .platforms import ProxmoxCheck, TrueNASCheck, VSphereCheck
from .snmp import SnmpCheck
from .ssh import DockerCheck, LinuxCheck
from .windows import WinRMCheck, WmiCheck

REGISTRY: dict[str, type[Check]] = {
    "ping": PingCheck,
    "tcp": TcpCheck,
    "http": HttpCheck,
    "dns": DnsCheck,
    "tls_cert": TlsCertCheck,
    "snmp": SnmpCheck,
    "winrm": WinRMCheck,
    "wmi": WmiCheck,
    "mqtt": MqttCheck,
    "linux": LinuxCheck,
    "docker": DockerCheck,
    "truenas": TrueNASCheck,
    "proxmox": ProxmoxCheck,
    "vsphere": VSphereCheck,
    "homeassistant": HomeAssistantCheck,
    "unifi_network": UniFiNetworkCheck,
    "unifi_protect": UniFiProtectCheck,
    "technitium": TechnitiumCheck,
}


def build_check(monitor: Any, config: Config) -> Check:
    return REGISTRY[monitor.type](monitor, config)


__all__ = ["Check", "CheckResult", "Result", "REGISTRY", "build_check"]
