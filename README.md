# EUDR Information System status page

A public page that shows whether the EU's EUDR Information System (TRACES NT) is reachable. A Python script checks the system every 10 minutes and writes the results to `site/status.json`. The page in `site/` reads that file.

## What is checked

Production, without credentials:

- TLS handshake and certificate expiry for `eudr.webcloud.ec.europa.eu`
- The TRACES NT web application at `/tracesnt/`
- The V3 due diligence statement WSDL
- The V3 simplified declaration WSDL

Acceptance:

- TLS handshake and certificate expiry
- The Echo Service WSDL
- A signed Echo call with Sourcemap's acceptance credentials

A V3 WSDL that returns 404 shows as "Not published." The Commission's documentation says the V3 endpoints open when the amended system goes live, so this is the expected result until then.

Credential, timestamp, and client ID faults on the Echo call show as "Not configured." These come from the probe's setup, and the page keeps them apart from outages on the Commission's side.

## Certificate chains

Some servers send their own certificate without the intermediate certificate that links it to a trusted root. Browsers fetch the missing intermediate on their own, so the site works in a browser. Python does not. When the probe sees this error, it fetches the intermediate from the address listed in the server certificate, retries, and notes the gap on the page. Any other certificate error, such as an expired certificate or a wrong hostname, counts as down.

## Limits

Production is checked without credentials. An "Up" result there means the server answered. It does not confirm that signed DDS submissions succeed. When Sourcemap has production credentials, add a narrow retrieval call that should return an empty result. The Commission's documentation recommends this as the production connectivity test.

The results reflect what the system returned to the probe host. They are not an official status from the European Commission.

The first runs have not been tested against the live endpoints, since this was built without network access. Check the first results by hand. In particular, confirm whether the production WSDLs are served without sign-in.

## Setup on GitHub

1. Create a repository and push this folder to `main`.
2. In Settings, then Pages, set the source to GitHub Actions.
3. In Settings, then Secrets and variables, then Actions, add `EUDR_ACC_USERNAME`, `EUDR_ACC_AUTH_KEY`, and `EUDR_ACC_CLIENT_ID`. The client ID is in the Web Services Access section of the TRACES profile.
4. Run the workflow once from the Actions tab. It then runs every 10 minutes.

Result history is kept on a `status-data` branch as a single commit, so the repository does not grow with every run. Seven days of history are retained.

GitHub starts scheduled runs late during busy periods. For tighter timing, run the probe on a Sourcemap server instead.

## Setup on a Sourcemap server

Use Python 3.9 or later, and install one package with `pip install cryptography`. The probe uses it only when a server omits an intermediate certificate.

```
*/10 * * * * cd /opt/eudr-status && EUDR_ACC_USERNAME=... EUDR_ACC_AUTH_KEY=... EUDR_ACC_CLIENT_ID=... python3 probe.py site/status.json
```

Serve the `site/` folder with any static web server. Keep the credentials in the server's secret store, never in the `site/` folder.

## Changing the checks

Endpoints, thresholds, and the check interval are constants at the top of `probe.py`. If the interval changes, change the cron schedule to match.

## Fonts and logo

The page uses Montserrat from `site/assets/fonts/`. `OFL.txt` must stay with the font files. The logo files in `site/assets/` are the approved Sourcemap artwork. The page shows the navy version on light screens and the white version in dark mode.
