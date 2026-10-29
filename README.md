# NHQM SSL Monitor

**Know when your certificates expire. Verify TLS connections with confidence.**

NHQM SSL Monitor is a lightweight Python package that validates website TLS certificates using the operating system's trusted certificate authorities, checks hostname matches, and reports expiration dates and warning thresholds.

## Features

- TLS certificate and hostname validation using Python's built-in `ssl` library
- Certificate expiration date and remaining days
- Configurable expiration warning threshold (default: 30 days)
- Issuer and subject information
- Simple CLI and Python API with JSON output
- No third-party runtime dependencies
- Python 3.9+

## Install

From the source directory:

```bash
python -m pip install -e .
```

After publishing to PyPI (not published yet):

```bash
pip install nhqm-ssl-monitor
```

## CLI

```bash
nhqm-ssl example.com
nhqm-ssl example.com --warning-days 14 --json
python -m nhqm_ssl_monitor example.com --port 443
```

Exit codes: `0` for a verified certificate outside the warning period; `1` for a warning, expired/invalid certificate, or connection failure; `2` for invalid CLI arguments.

## Python API

```python
from nhqm_ssl_monitor import check_certificate

status = check_certificate("example.com", warning_days=30)
if status.valid:
    print("Expires:", status.expires_at)
    print("Days remaining:", status.days_remaining)
else:
    print("Verification failed:", status.error)

if status.warning:
    print("Action required: certificate issue or approaching expiration")
```

The `CertificateStatus` object also supports `to_dict()` for JSON serialization.

## Automated checks

Schedule the CLI via Windows Task Scheduler, cron, or GitHub Actions. For example, run `nhqm-ssl example.com --warning-days 14` daily and alert when it exits with status `1`.

## Security and limitations

- This tool performs a live TLS handshake. It **does not** inspect certificate revocation status (OCSP/CRL), all intermediate certificate details, or every endpoint behind a load balancer.
- An invalid/expired certificate cannot be inspected for expiration metadata through the verified connection; the result returns `valid=False` with an error instead. Never disable certificate verification just to extract expiry information in security-sensitive workflows.
- Do not pass attacker-controlled hostnames directly to this library in a web service: doing so can enable SSRF or access to internal network services. Apply network egress controls and destination allowlists.
- Checks run only when called; this package does not include a background monitoring service, notification delivery, or dashboard.
- PyPI project name availability has not been checked; no release has been published.

## Tests

```bash
python -m unittest discover -s tests -v
```

## License

MIT (see LICENSE).
