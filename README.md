# SiteBrush: Simplifying Web Creation for Bloggers.

<img src='https://repository-images.githubusercontent.com/429163995/331b95fa-4309-4d25-8c1a-0e8f34ff7b25' align="right">

## Try It: [sitebrush.com](http://sitebrush.com)
## Get It: [download](http://files.matveynator.ru/sitebrush/latest/)

Creating a blog or web page should be easy. SiteBrush makes it happen by streamlining the process, letting you focus on creativity.

**Dynamic Sites' Drawbacks:**
* No live preview during edits.
* Complex template handling.
* Limited design customization.
* Very slow.
* Security concerns.

**Static Sites' Drawbacks:**
* Manual page edits and uploads.
* Tedious changes across multiple pages.
* Collaboration challenges.

**Advantages of SiteBrush:**
* **Visual and Code Editing:** Make changes in both visual and text mode.
* **Revision Control:** Keep track of versions for your edits.
* **Dynamic Site Built from Static Files:** Edit dynamically and save changes to static files.
* **Effortless Updates – Think "Templates":** Easily modify thousands of identical elements across pages.
* **Automatic File Integration:** Seamlessly integrate all external files.
* **Eliminate 404 errors:** Automatically preserve old and new page URLs .
* **Freeze Feature:** Privately preview changes before publishing.
* **Backup:** Save backups of your content in static full page archive.


## Container runtime

SiteBrush v2 runs as a minimal Go web service by default. The GUI build is opt-in
with `-tags gui`; the Docker image intentionally builds the non-GUI service.

### Build and run

```sh
docker build -t sitebrush:local .
docker run --rm -p 2444:2444 \
  -e SITEBRUSH_ADMIN_PASSWORD_SHA256='<sha256-of-admin-password>' \
  -e SITEBRUSH_ALLOWED_HOSTS='localhost,127.0.0.1' \
  -v sitebrush-data:/data \
  -v "$PWD/public_html:/public_html" \
  sitebrush:local
```

The image starts:

```sh
sitebrush -web-path /public_html -db-path /data -db-type sqlite
```

It exposes port `2444`, runs as a non-root user, and declares `/data` and
`/public_html` as volumes. `/public_html` is the editable/served site root.
`/data` holds the SQLite database file and SiteBrush archive metadata.

### Configuration

Runtime flags:

| Flag | Default in image | Purpose |
| --- | --- | --- |
| `-web-port` | `2444` | HTTP port inside the container. |
| `-web-path` | `/public_html` | Writable public site root. |
| `-web-index-file` | `index.html` | Default index file. |
| `-db-path` | `/data` | Writable database/archive root. |
| `-db-type` | `sqlite` | Database driver for the container service. |
| `-db-save-interval` | `30s` | In-memory database flush interval. |
| `-timezone` | `UTC` | Time zone used by the service. |

Environment variables:

| Variable | Required | Purpose |
| --- | --- | --- |
| `SITEBRUSH_ADMIN_PASSWORD_SHA256` | Recommended | Hex SHA-256 of the bootstrap admin password. Treat it as a secret password verifier and inject it with runtime/orchestrator secrets. |
| `SITEBRUSH_ADMIN_PASSWORD` | Alternative | Plaintext bootstrap admin password when a hash is not provided. Use only via a runtime/orchestrator secret. |
| `SITEBRUSH_ALLOWED_HOSTS` | Recommended | Comma-separated public host allow-list used for trusted domain-specific metadata. Local loopback hosts are allowed for local development only. |

If no persistent users exist and neither admin password variable is configured,
the login screen returns `503` with setup guidance.

Uploads are capped at 10 MiB per request body and active HTML/CSS/JS uploads are
rejected for generic file uploads. Image uploads are decoded and validated before
being stored under the media path.

Backups are created only through the authenticated backup action and are written
under the archive root derived from `-db-path`:

```text
<db-path>/sitebrush-archives/<site-hash>/backups/
```

The service rejects backup destinations inside the public web root, so backup
ZIPs are not publicly exposed by the default container layout. Keep `/data`
mounted separately from `/public_html`.

### Health checks

Use either endpoint for readiness:

```sh
curl -fsS http://localhost:2444/sitebrush-healthz
curl -fsS 'http://localhost:2444/?health'
```

The health check returns JSON with `{"status":"ok"}` only when the public web
root and archive root are directories and writable. Failures return `503` with a
generic `{"status":"unavailable"}` response and do not include local paths or
secret values.
