#!/usr/bin/env python3
"""Probe the EUDR Information System (TRACES NT) and record the results.

Each run checks every endpoint once and appends one result per check to
status.json. The status page reads that file. It needs Python 3.9 or later and the standard
library for the checks. When a server omits an intermediate certificate, the
probe fetches it with the `cryptography` package (pip install cryptography).

Production is checked without credentials: TLS, the web application, and
the published WSDL files. Acceptance also gets an authenticated call to the
Echo Service when these environment variables are set:

    EUDR_ACC_USERNAME     web service username
    EUDR_ACC_AUTH_KEY     web service authentication key
    EUDR_ACC_CLIENT_ID    WebServiceClientId from the Web Services Access profile section

Usage: python3 probe.py [path/to/status.json]
"""

import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PROD = "eudr.webcloud.ec.europa.eu"
ACC = "acceptance.eudr.webcloud.ec.europa.eu"

INTERVAL_MINUTES = 10          # match the scheduler; the page uses it to size the history strip
KEEP_DAYS = 7                  # history retained in status.json
TIMEOUT_S = 20                 # a request that takes longer counts as down
SLOW_MS = 3000                 # HTTP checks slower than this are marked slow
SLOW_ECHO_MS = 5000            # the Echo call is allowed more time
CERT_WARN_DAYS = 14            # warn when the TLS certificate expires within this many days

# States, worst first. The page ranks checks in this order.
#   down        no usable response
#   slow        responded, but over the latency threshold (or a certificate near expiry)
#   unpublished the endpoint answered 404; expected for V3 until the Commission opens it
#   unconfigured no credentials, or credentials rejected; a Sourcemap-side issue
#   up          responded normally


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Count a redirect as a response. Following it would test EU Login as well."""

    def redirect_request(self, *args, **kwargs):
        return None


USER_AGENT = "Sourcemap-EUDR-status-probe/1.0 (+https://sourcemap.com)"

# Intermediate certificates fetched for hosts that do not send their full chain.
# Browsers fetch a missing intermediate from the address in the certificate
# (the AIA field). Python does not, so the probe does the same step itself.
EXTRA_CA = {}


def tls_context(host):
    ctx = ssl.create_default_context()
    if EXTRA_CA.get(host):
        ctx.load_verify_locations(cadata=EXTRA_CA[host])
    return ctx


def opener_for(url):
    host = urllib.parse.urlsplit(url).hostname
    return urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=tls_context(host)))


def fetch_intermediates(host):
    """Follow the AIA 'CA Issuers' links from the server certificate. Return PEM text."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

    unverified = ssl.create_default_context()
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=TIMEOUT_S) as sock:
        with unverified.wrap_socket(sock, server_hostname=host) as tls:
            cert = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))

    pems = []
    for _ in range(4):
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        except x509.ExtensionNotFound:
            break
        urls = [d.access_location.value for d in aia
                if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
        if not urls:
            break
        req = urllib.request.Request(urls[0], headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            data = resp.read()
        issuer = None
        for load in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
            try:
                issuer = load(data)
                break
            except ValueError:
                pass
        if issuer is None:  # some CAs publish a PKCS#7 bundle
            bundle = pkcs7.load_der_pkcs7_certificates(data)
            issuer = bundle[0] if bundle else None
        if issuer is None:
            break
        pems.append(issuer.public_bytes(Encoding.PEM).decode())
        if issuer.issuer == issuer.subject:
            break
        cert = issuer
    return "".join(pems)


def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_get(url):
    """Return (status_code or None, elapsed_ms, error_text or None)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    start = time.monotonic()
    try:
        with opener_for(url).open(req, timeout=TIMEOUT_S) as resp:
            resp.read(65536)
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:  # DNS failure, refused connection, timeout, TLS error
        reason = getattr(e, "reason", e)
        detail = getattr(reason, "verify_message", None) or type(reason).__name__
        return None, round((time.monotonic() - start) * 1000), detail
    return code, round((time.monotonic() - start) * 1000), None


def _handshake(host):
    start = time.monotonic()
    with socket.create_connection((host, 443), timeout=TIMEOUT_S) as sock:
        with tls_context(host).wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    return cert, round((time.monotonic() - start) * 1000)


def check_tls(host):
    completed = False
    try:
        cert, ms = _handshake(host)
    except ssl.SSLCertVerificationError as e:
        reason = e.verify_message or str(e)
        if "local issuer" not in reason:
            # Expired, wrong hostname, or untrusted root: a real certificate fault.
            return {"state": "down", "ms": None, "note": f"Certificate rejected: {reason}"}
        try:
            EXTRA_CA[host] = fetch_intermediates(host)
            cert, ms = _handshake(host)
            completed = True
        except Exception as e2:
            EXTRA_CA.pop(host, None)
            return {"state": "down", "ms": None,
                    "note": f"Certificate rejected: {reason}; fetching the missing intermediate failed ({type(e2).__name__})"}
    except Exception as e:
        return {"state": "down", "ms": None, "note": f"TLS connection failed ({type(e).__name__})"}

    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    days = (expires - dt.datetime.now(dt.timezone.utc)).days
    note = f"Certificate valid for {days} more days"
    if completed:
        note += ". The server omits an intermediate certificate, which browsers fetch on their own"
    if days < CERT_WARN_DAYS:
        return {"state": "slow", "ms": ms, "note": f"Certificate expires in {days} days"}
    return {"state": "slow" if ms > SLOW_MS else "up", "ms": ms, "note": note}


def check_web(url):
    code, ms, err = http_get(url)
    if code is None:
        return {"state": "down", "ms": None, "note": f"No response ({err})"}
    if code >= 500:
        return {"state": "down", "ms": ms, "code": code, "note": f"Server error {code}"}
    if code == 404:
        return {"state": "down", "ms": ms, "code": code, "note": "Page not found"}
    return {"state": "slow" if ms > SLOW_MS else "up", "ms": ms, "code": code,
            "note": f"Responded with HTTP {code}"}


def check_wsdl(url):
    code, ms, err = http_get(url)
    if code is None:
        return {"state": "down", "ms": None, "note": f"No response ({err})"}
    if code >= 500:
        return {"state": "down", "ms": ms, "code": code, "note": f"Server error {code}"}
    if code == 404:
        return {"state": "unpublished", "ms": ms, "code": code, "note": "The server answered 404 for this WSDL"}
    if code in (401, 403):
        note = "Server responded; the WSDL requires sign-in"
    elif 300 <= code < 400:
        note = f"Server responded with a redirect (HTTP {code})"
    else:
        note = "WSDL served"
    return {"state": "slow" if ms > SLOW_MS else "up", "ms": ms, "code": code, "note": note}


def password_digest(nonce, created, key):
    """WS-Security UsernameToken digest: Base64(SHA-1(nonce + created + key))."""
    return base64.b64encode(hashlib.sha1(nonce + created.encode() + key.encode()).digest()).decode()


def echo_envelope(username, key, client_id):
    created_dt = dt.datetime.now(dt.timezone.utc)
    created = created_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{created_dt.microsecond // 1000:03d}Z"
    expires_dt = created_dt + dt.timedelta(minutes=5)
    expires = expires_dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{expires_dt.microsecond // 1000:03d}Z"
    nonce = secrets.token_bytes(16)
    return f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:echo="http://ec.europa.eu/tracesnt/eudr/echo"
                  xmlns:base="http://ec.europa.eu/sanco/tracesnt/base/v4">
  <soapenv:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsu:Timestamp>
        <wsu:Created>{created}</wsu:Created>
        <wsu:Expires>{expires}</wsu:Expires>
      </wsu:Timestamp>
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest(nonce, created, key)}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{base64.b64encode(nonce).decode()}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
    <base:WebServiceClientId>{client_id}</base:WebServiceClientId>
  </soapenv:Header>
  <soapenv:Body>
    <echo:EudrEchoRequest>
      <echo:query>status probe</echo:query>
    </echo:EudrEchoRequest>
  </soapenv:Body>
</soapenv:Envelope>"""


def check_echo(host):
    username = os.environ.get("EUDR_ACC_USERNAME")
    key = os.environ.get("EUDR_ACC_AUTH_KEY")
    client_id = os.environ.get("EUDR_ACC_CLIENT_ID")
    if not (username and key and client_id):
        return {"state": "unconfigured", "ms": None, "note": "Credentials not set on the probe host"}

    body = echo_envelope(username, key, client_id).encode()
    req = urllib.request.Request(
        f"https://{host}/tracesnt/ws/EudrEchoService", data=body, method="POST",
        headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""', "User-Agent": USER_AGENT})
    start = time.monotonic()
    try:
        with opener_for(req.full_url).open(req, timeout=TIMEOUT_S) as resp:
            code, text = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        code, text = e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        reason = getattr(e, "reason", e)
        detail = getattr(reason, "verify_message", None) or type(reason).__name__
        return {"state": "down", "ms": None, "note": f"No response ({detail})"}
    ms = round((time.monotonic() - start) * 1000)

    status = re.search(r"<(?:\w+:)?status>\s*([^<]+?)\s*</", text)
    if code == 200 and status and status.group(1).upper() == "OK":
        return {"state": "slow" if ms > SLOW_ECHO_MS else "up", "ms": ms, "code": code,
                "note": "Authenticated test call succeeded"}

    fault = re.search(r"<(?:\w+:)?errorMessage>\s*([^<]+?)\s*</", text) or \
        re.search(r"<faultstring>\s*([^<]+?)\s*</faultstring>", text)
    message = fault.group(1) if fault else f"HTTP {code}"
    # Credential, clock and header faults come from the probe's own setup, so they
    # are reported separately from an outage on the Commission's side.
    if re.search(r"authenticat|timestamp|expired|WebServiceClientId|unauthori", message, re.I):
        return {"state": "unconfigured", "ms": ms, "code": code, "note": f"Rejected by the service: {message}"}
    return {"state": "down", "ms": ms, "code": code, "note": f"Service fault: {message}"}


CHECKS = [
    # id, environment, display name, plain description, function, argument
    ("prod-tls", "production", "Secure connection",
     "Checks the TLS handshake and certificate for the production host.", check_tls, PROD),
    ("prod-web", "production", "Web application",
     "Checks that the production TRACES NT application answers.", check_web, f"https://{PROD}/tracesnt/"),
    ("prod-dds-v3", "production", "Due diligence statement service, V3",
     "Checks whether the V3 DDS service description (WSDL) is served.", check_wsdl,
     f"https://{PROD}/tracesnt/ws/EUDRDueDiligenceStatementServiceV3?wsdl"),
    ("prod-sd-v3", "production", "Simplified declaration service, V3",
     "Checks whether the V3 simplified declaration service description (WSDL) is served.", check_wsdl,
     f"https://{PROD}/tracesnt/ws/EUDRSimplifiedDeclarationServiceV3?wsdl"),
    ("acc-tls", "acceptance", "Secure connection",
     "Checks the TLS handshake and certificate for the acceptance host.", check_tls, ACC),
    ("acc-echo-wsdl", "acceptance", "Echo service description",
     "Checks whether the acceptance Echo Service WSDL is served.", check_wsdl,
     f"https://{ACC}/tracesnt/ws/EudrEchoService?wsdl"),
    ("acc-echo", "acceptance", "Authenticated test call",
     "Sends a signed Echo request with Sourcemap's acceptance credentials and expects OK.", check_echo, ACC),
]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join("site", "status.json")
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    history = {c["id"]: c.get("history", []) for c in data.get("checks", [])}
    keep = KEEP_DAYS * 24 * 60 // INTERVAL_MINUTES
    stamp = now_iso()

    checks = []
    for cid, env, name, desc, fn, arg in CHECKS:
        result = fn(arg)
        result = {k: v for k, v in result.items() if v is not None}
        entry = {"t": stamp, **result}
        past = (history.get(cid, []) + [entry])[-keep:]
        checks.append({"id": cid, "env": env, "name": name, "description": desc, "history": past})
        print(f"{cid:14} {entry['state']:12} {entry.get('ms', '-')!s:>6} ms  {entry.get('note', '')}")

    out = {"generated": stamp, "interval_minutes": INTERVAL_MINUTES, "checks": checks}
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out, f, separators=(",", ":"))
    os.replace(tmp, path)


if __name__ == "__main__":
    main()
