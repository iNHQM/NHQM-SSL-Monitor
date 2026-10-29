"""Command line entry point: python -m nhqm_ssl_monitor example.com."""
import argparse
import json
from .core import check_certificate


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a site's TLS certificate")
    parser.add_argument("hostname", help="DNS hostname, e.g. example.com")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--warning-days", type=int, default=30)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()
    try:
        status = check_certificate(args.hostname, port=args.port,
                                   timeout=args.timeout, warning_days=args.warning_days)
    except ValueError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(status.to_dict(), indent=2))
    else:
        print(f"Host: {status.hostname}:{status.port}")
        print(f"Verified: {'YES' if status.valid else 'NO'}")
        if status.expires_at:
            print(f"Expires: {status.expires_at.isoformat()}")
            print(f"Days remaining: {status.days_remaining}")
            print(f"Issuer: {status.issuer}")
        if status.warning:
            print("WARNING: certificate problem or approaching expiration")
        if status.error:
            print(f"Error: {status.error}")
    return 0 if status.valid and not status.warning else 1


if __name__ == "__main__":
    raise SystemExit(main())
