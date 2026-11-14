"""Offline IP -> country / network (ASN) lookups, so IPs never leave this host.

Uses the free DB-IP Lite databases (https://db-ip.com, CC BY 4.0: "IP Geolocation by
DB-IP"), monthly MMDB files kept in state/geoip/: dbip-country-lite.mmdb and
dbip-asn-lite.mmdb. The daily run calls update(), which downloads a file only when it
is missing or older than MAX_AGE (current month first, then the previous one, since a
new month's file can appear late). Everything is best-effort: without the files,
lookup() returns {} and callers carry on without location.

    python -m router_agent.geoip --update        # download now
    python -m router_agent.geoip 203.0.113.7     # look up an IP
"""
import argparse
import gzip
import ipaddress
import logging
import os
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

logger = logging.getLogger(__name__)

DEFAULT_DIR = Path(__file__).resolve().parents[1] / "state" / "geoip"
URL = "https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz"
KINDS = ("country", "asn")
MAX_AGE = timedelta(days=32)

_readers: dict[str, tuple[float, object]] = {}  # path -> (mtime, maxminddb.Reader)


def _path(kind: str, base: Path | None = None) -> Path:
    return Path(base or DEFAULT_DIR) / f"dbip-{kind}-lite.mmdb"


def _reader(kind: str, base: Path | None = None):
    p = _path(kind, base)
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return None
    cached = _readers.get(str(p))
    if cached and cached[0] == mtime:
        return cached[1]
    import maxminddb

    r = maxminddb.open_database(str(p))
    _readers[str(p)] = (mtime, r)
    return r


def lookup(ip: str | None, base: Path | None = None) -> dict:
    """-> {"country": "RO", "asn": 8708, "as_org": "RCS & RDS"} (keys only when known). Never raises."""
    try:
        addr = ipaddress.ip_address((ip or "").strip())
        if not addr.is_global:
            return {}
    except ValueError:
        return {}
    out: dict = {}
    try:
        c = _reader("country", base)
        rec = c.get(str(addr)) if c else None
        if rec and (rec.get("country") or {}).get("iso_code"):
            out["country"] = rec["country"]["iso_code"]
        a = _reader("asn", base)
        rec = a.get(str(addr)) if a else None
        if rec and rec.get("autonomous_system_number"):
            out["asn"] = int(rec["autonomous_system_number"])
            if rec.get("autonomous_system_organization"):
                out["as_org"] = rec["autonomous_system_organization"]
    except Exception as e:
        logger.info("geoip lookup failed: %s", e)
    return out


def network_key(info: dict) -> str | None:
    """The identity of 'a network' for new-network detection: the ASN (an ISP / carrier)."""
    return f"AS{info['asn']}" if info.get("asn") else None


def describe(info: dict) -> str:
    """'RCS & RDS (AS8708), RO'."""
    org = info.get("as_org") or ""
    asn = f"AS{info['asn']}" if info.get("asn") else ""
    who = f"{org} ({asn})" if org and asn else org or asn
    return ", ".join(x for x in (who, info.get("country") or "") if x)


def _months(now: datetime) -> list[str]:
    first = now.replace(day=1)
    return [first.strftime("%Y-%m"), (first - timedelta(days=1)).strftime("%Y-%m")]


def _download(kind: str, dest: Path, now: datetime) -> bool:
    import maxminddb

    for month in _months(now):
        url = URL.format(kind=kind, month=month)
        try:
            with requests.get(url, stream=True, timeout=60) as r:
                if r.status_code != 200:
                    continue
                fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=f".{kind}-", suffix=".mmdb")
                try:
                    with os.fdopen(fd, "wb") as f, gzip.GzipFile(fileobj=r.raw) as gz:
                        shutil.copyfileobj(gz, f)
                    maxminddb.open_database(tmp).close()  # refuse a truncated/corrupt file
                    os.chmod(tmp, 0o644)
                    os.replace(tmp, dest)
                    return True
                finally:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
        except Exception as e:
            logger.warning("geoip: %s download failed (%s): %s", kind, month, e)
    return False


def update(base: Path | None = None, now: datetime | None = None, force: bool = False) -> list[str]:
    """Download missing or old databases. Returns the kinds updated. Never raises."""
    now = now or datetime.now(UTC)
    done = []
    try:
        d = Path(base or DEFAULT_DIR)
        d.mkdir(parents=True, exist_ok=True)
        for kind in KINDS:
            p = _path(kind, d)
            fresh = p.exists() and now - datetime.fromtimestamp(p.stat().st_mtime, UTC) < MAX_AGE
            if (force or not fresh) and _download(kind, p, now):
                done.append(kind)
    except Exception as e:
        logger.warning("geoip update failed: %s", e)
    return done


def main() -> None:
    ap = argparse.ArgumentParser(description="Offline IP -> country/ASN (DB-IP Lite)")
    ap.add_argument("ip", nargs="*")
    ap.add_argument("--update", action="store_true", help="download the databases if missing or old")
    ap.add_argument("--force", action="store_true", help="with --update: download even if fresh")
    args = ap.parse_args()
    if args.update:
        print("updated:", ", ".join(update(force=args.force)) or "nothing (already fresh, or download failed)")
    for ip in args.ip:
        print(ip, lookup(ip) or "unknown", describe(lookup(ip)))


if __name__ == "__main__":
    main()
