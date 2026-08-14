from __future__ import annotations

from ipaddress import ip_address, ip_network

from .models import Alert, EnrichedAlert, Severity


KNOWN_BAD_NETWORKS = (
    ip_network("198.51.100.0/28"),
    ip_network("203.0.113.64/28"),
)

ASSETS = {
    "10.0.0.10": ("public-web-01", Severity.critical),
    "10.0.0.20": ("identity-01", Severity.critical),
    "10.0.0.30": ("file-server-01", Severity.high),
}

SERVICES = {21: "ftp", 22: "ssh", 53: "dns", 80: "http", 443: "https", 445: "smb", 3389: "rdp"}


def enrich(alert: Alert) -> EnrichedAlert:
    src = ip_address(alert.src_ip)
    dst = ip_address(alert.dst_ip)
    asset, criticality = ASSETS.get(alert.dst_ip, ("unmanaged-endpoint", Severity.medium))
    total_packets = alert.packets_forward + alert.packets_backward
    if not src.is_private and dst.is_private:
        direction = "inbound"
    elif src.is_private and not dst.is_private:
        direction = "outbound"
    elif src.is_private and dst.is_private:
        direction = "internal"
    else:
        direction = "external"

    return EnrichedAlert(
        **alert.model_dump(),
        src_is_private=src.is_private,
        dst_is_private=dst.is_private,
        src_known_bad=any(src in network for network in KNOWN_BAD_NETWORKS),
        dst_asset=asset,
        dst_asset_criticality=criticality,
        destination_service=SERVICES.get(alert.dst_port, "other"),
        bytes_per_packet=round(alert.payload_bytes / max(total_packets, 1), 2),
        direction=direction,
    )

