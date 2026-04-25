---
title: SiteBrush MVP Scope and Behavior Contracts
status: draft
---

# SiteBrush MVP Scope and Behavior Contracts

This document turns the current README promises and prototype Go handlers into
implementation-ready contracts for the next hardening pass. It intentionally
describes the MVP behavior to build, not all future SiteBrush ideas. Current
handlers are mostly placeholders; requirements marked as contracts below are
target MVP behavior unless the text explicitly says "current".

## MVP goal

SiteBrush should run as a small local or self-hosted web editor for an existing
static site:

1. Serve files from a configured `WEB_FILE_PATH`.
2. Let an authenticated operator edit and save page content in a practical
   text/code editing flow. A richer WYSIWYG visual editor can build on the same
   save/revision contract later.
3. Keep revisions for edited pages.
4. Support navigation metadata, page properties, freeze/unfreeze preview flow,
   and static backups.
5. Persist operational state in the database while preserving the edited static
   files as the source that visitors can read.
6. Keep the default build CLI/non-GUI; launch an optional WebView shell only
   when built with the `gui` tag and started with `-gui`.

### Non-goals for this hardening pass

- No multi-tenant SaaS administration.
- No unrelated CMS features such as comments, analytics, newsletters, or media
  marketplaces.
- No full template language implementation beyond documenting the update model
  required for future "template-like" shared edits.
- No full visual page-builder/WYSIWYG editor in this pass; the MVP contract is
  authenticated text/code editing with safe persistence.
- No automatic discovery, import, or bundling of every external asset reference.
  Existing assets under `WEB_FILE_PATH` are served and protected by the same
  path-safety rules; broader "automatic file integration" is deferred.
- No automatic redirect/alias management for every old and new URL. The MVP
  must avoid creating broken links during its own edit/save/navigation actions,
  but a complete "eliminate 404 errors" feature is deferred.
- No public REST API guarantee beyond the HTTP action contract below.
- No mandatory GUI dependency in default builds.
- No schema migration framework unless the MVP fields cannot be added safely
  with straightforward `CREATE TABLE IF NOT EXISTS` / additive `ALTER TABLE`
  steps.

The current README describes several long-term SiteBrush advantages, including
automatic file integration and eliminating 404 errors. For this Go hardening
MVP, treat those as product direction rather than completed v2 scope. This
contract intentionally narrows them to safe local asset serving and avoiding
links broken by SiteBrush's own edits.

## Users, personas, and operating modes

| Persona | Needs | MVP permissions |
| --- | --- | --- |
| Visitor | Reads the public static site. | Can request static files only. |
| Site operator | Edits content, reviews revisions, manages backups, and publishes frozen changes. | Can authenticate and use all editing actions. |
| Local desktop user | Runs SiteBrush on a workstation and prefers an app window. | Same as site operator, through optional WebView GUI shell. |
| Maintainer | Runs tests, builds releases, and hardens internals. | Does not get runtime privileges by default. |

Operating modes:

- **CLI/non-GUI server (default):** `go build ./...` and the default binary must
  start the HTTP server without WebView system dependencies.
- **Optional GUI shell:** `go build -tags gui` may include WebView support.
  Runtime `-gui` opens the local server URL in a WebView window; without `-gui`,
  the GUI build should behave like the CLI server.
- **Database backends:** the code currently wires Genji, SQLite, and PostgreSQL
  driver choices. Genji/SQLite are the primary embedded MVP validation targets;
  PostgreSQL must be treated as driver-wired but not contract-validated until
  table creation and save queries are verified for that backend.

## HTTP route/action contract

Current dispatch is a single catch-all handler that resolves
`request.URL.Path` to a file and switches on the raw query string
(`?edit`, `?login`, and similar). The MVP may keep this shape to minimize
scope, but each action must have explicit method, auth, CSRF, and status-code
rules. A later refactor should move these to explicit routes or a structured
action parser.

Current security state is not production-safe: file paths are concatenated from
the request path, and authentication is stubbed to always return true. The
contracts below are required target behavior for the MVP implementation, not a
description of the current handler security.

Example current-style URLs:

```text
/about/?edit
/about/?revisions
/?login
/?backup
```

| Action | Current query | Methods | Auth | Contract |
| --- | --- | --- | --- | --- |
| Static file | no query | `GET`, `HEAD` | No | Serve the resolved file from `WEB_FILE_PATH`; return `404` for missing files and `403` for unsafe paths. |
| Login | `?login` | `GET`, `POST` | No | `GET` shows login form; `POST` validates credentials, creates a session, and redirects to the requested page or profile. |
| Edit/save | `?edit` | `GET`, `POST` | Yes | `GET` shows editor for a safe existing page or a permitted new page; `POST` validates CSRF and saves content plus revision metadata. |
| Delete revision | `?delete` | `POST` | Yes | Deletes or marks deleted the latest editable revision for the page; never deletes the live static file without an explicit restore/publish operation. |
| Revisions | `?revisions` | `GET`, optional `POST` for restore | Yes | Lists revisions for the page. Restore, if implemented in this action, must be a CSRF-protected `POST`. |
| Subpages | `?subpages` | `GET`, `POST` | Yes | Shows or updates child-page/navigation metadata for the current page. |
| Properties | `?properties` | `GET`, `POST` | Yes | Shows or updates title, tags, status, and publish metadata for the current page. |
| Freeze | `?freeze` | `POST` | Yes | Enables private preview/frozen-edit mode. Must not expose draft content to unauthenticated visitors. |
| Unfreeze | `?unfreeze` | `POST` | Yes | Publishes or exits frozen mode according to the freeze contract below. |
| Backup | `?backup` | `POST` | Yes | Creates a static archive/backup after safety checks. |
| Profile | `?profile` | `GET`, `POST` | Yes | Shows account/session information and allows safe profile settings that do not leak credentials. |
| Logout | `?logout` | `POST` preferred; `GET` may show confirmation | Yes | Invalidates the session cookie and redirects to login or the current page. |

If raw-query dispatch remains temporarily, only one action token is valid at a
time. Unknown query strings must not fall through to static serving with
privileged behavior.

## User stories and acceptance criteria

### Static serving

**Story:** As a visitor, I can browse the static site normally.

Acceptance criteria:

- `GET /` serves `WEB_FILE_PATH/WEB_INDEX_FILE`.
- `GET /docs/` serves `WEB_FILE_PATH/docs/WEB_INDEX_FILE`.
- `GET /assets/site.css` serves the file only if it resolves inside
  `WEB_FILE_PATH`.
- Missing files return `404`; unsafe paths return `403` or `404` without
  revealing filesystem details.
- Content type and `HEAD` behavior are consistent with Go static serving.

### Login and session

**Story:** As a site operator, I can sign in before using editing actions.

Acceptance criteria:

- Unauthenticated mutating or private actions redirect to login or return
  `401/403`.
- Current code does not meet this yet: `checkUserLoggedIn` is a placeholder that
  returns true for every request. Replacing that stub is mandatory before any
  write-capable action is considered usable.
- Passwords or tokens are never logged or stored in plain text.
- Sessions use secure, HTTP-only cookies where deployment allows, with
  expiration and logout invalidation.
- Failed login attempts return a generic error and do not reveal which field
  was wrong.

### Edit and save

**Story:** As a site operator, I can edit a page and save it back to the static
site.

Acceptance criteria:

- `GET ?edit` loads the current static content and metadata for a safe path.
- `POST ?edit` requires authentication and CSRF validation.
- Saving writes the intended file atomically, creates a revision record, and
  preserves previous content for rollback.
- Failed saves must not corrupt the existing file, must clean up temporary files
  where possible, and must return a clear error that the save did not complete.
- Concurrent edits have deterministic behavior: either reject stale submissions
  with a conflict response or create a new revision with clear ordering.

### Revisions

**Story:** As a site operator, I can inspect previous versions of a page.

Acceptance criteria:

- Revision list is scoped by domain/site and request URI.
- Each revision has editor, timestamp, title/status metadata, and content or a
  pointer to archived content.
- Deleting a revision is authenticated, CSRF-protected, and auditable.
- Restoring a revision creates a new current revision rather than silently
  rewriting history.

### Subpages and navigation

**Story:** As a site operator, I can view and adjust page hierarchy/navigation.

Acceptance criteria:

- Subpage tree is based on safe paths under `WEB_FILE_PATH` plus stored
  navigation metadata.
- Parent/child changes cannot point outside the site root.
- Navigation updates can be reflected in pages that share the same navigation
  block in a later template-like update phase.

### Properties and metadata

**Story:** As a site operator, I can edit page metadata separately from body
content.

Acceptance criteria:

- Properties include at least title, tags, status, published state, and request
  URI/domain association.
- Metadata saves create or update database records and, when necessary, update
  the static page consistently with the edit/save contract.
- Invalid metadata returns validation errors without modifying files.

### Freeze and unfreeze

**Story:** As a site operator, I can privately preview changes before publishing.

Acceptance criteria:

- Freeze mode records site state and routes authenticated previews to draft or
  frozen content without exposing drafts to visitors.
- Implementation must choose and document one concrete preview model before
  coding freeze behavior. Acceptable MVP options are a database-backed draft
  overlay for authenticated requests or filesystem shadow copies outside
  `WEB_FILE_PATH`; both must keep unauthenticated visitors on the published
  static files.
- Static visitor URLs remain stable during freeze.
- Unfreeze publishes approved changes or exits preview mode with clear rollback
  behavior.
- Freeze state persists across process restarts.

### Backup

**Story:** As a site operator, I can create a recoverable static archive.

Acceptance criteria:

- Backup includes static files and enough database metadata to understand
  revisions/properties.
- Backup destination is outside publicly served paths unless explicitly
  configured safe.
- Backup filenames include timestamp and site identity to avoid overwrites.
- Partial or failed backups leave a clear error and do not corrupt existing
  backups.

### Profile and logout

**Story:** As a site operator, I can view account/session state and sign out.

Acceptance criteria:

- Profile shows non-sensitive account information and current server/site
  identity.
- Profile updates, if any, are CSRF-protected.
- Logout invalidates the current session and prevents reuse of the old cookie.

### Database persistence

**Story:** As a maintainer/operator, I can restart SiteBrush without losing
revision and state data.

Acceptance criteria:

- Startup creates required tables if absent.
- Saves either complete fully or report a durable error; no silent loss from the
  save queue.
- Watchdog updates show database liveness without interfering with writes.
- Embedded database files are placed under `DB_FILE_PATH` using the current
  `sitebrush.<listener-hash>.db.<type>` naming convention unless explicitly
  changed in a later migration.

### GUI launch

**Story:** As a local desktop user, I can open a GUI window for the local server
when optional dependencies are available.

Acceptance criteria:

- Default non-GUI builds do not import or require WebView.
- GUI builds require `-tags gui`; `-gui` opens
  `http://LOCALHOST_LISTENER_ADDRESS`.
- If GUI dependencies are missing, CLI build/test validation remains the
  required baseline and the dependency blocker is documented.

## File layout and path-safety rules

Configuration fields already present:

- `WEB_FILE_PATH`: root directory for public static site files. Default:
  `public_html`.
- `WEB_INDEX_FILE`: index filename used for directory URLs. Default:
  `index.html`.
- `DB_FILE_PATH`: directory for database files. Default: current directory.
- `DB_FULL_FILE_PATH`: computed as
  `DB_FILE_PATH/sitebrush.<WEB_LISTENER_ADDRESS_HASH>.db.<DB_TYPE>`.

Rules for the MVP:

0. Current code does not meet these rules yet. Path safety is a critical target
   requirement for the next hardening implementation phase.
1. Resolve every requested path with URL unescaping, path cleaning, and a final
   containment check against the absolute `WEB_FILE_PATH`.
2. Treat `/` and paths ending in `/` as directory requests and append
   `WEB_INDEX_FILE`.
3. Do not allow `..`, symlink escapes, absolute-path injection, encoded
   traversal, or Windows drive-prefix escapes to read or write outside the site
   root.
4. Writes must be atomic where the platform allows: write a temporary sibling,
   fsync when practical, then rename over the target.
5. Revision/archive storage may be database-backed or file-backed, but file
   archives must live outside the public site root by default, for example:

   ```text
   <DB_FILE_PATH>/sitebrush-archives/<site-hash>/revisions/
   <DB_FILE_PATH>/sitebrush-archives/<site-hash>/backups/
   ```

6. Backup restore, if added, must verify that every archive member extracts
   inside the intended restore root before writing any file.

## Database contract

### Current tables

The prototype creates these tables:

```sql
CREATE TABLE IF NOT EXISTS DBWatchDog (
  Id INT PRIMARY KEY,
  UnixTime INT
);

CREATE TABLE IF NOT EXISTS Post (
  Id INTEGER PRIMARY KEY,
  OwnerId INTEGER,
  EditorId INTEGER,
  RequestUri TEXT,
  Date INTEGER,
  Title TEXT,
  Body TEXT,
  Header TEXT,
  Tags TEXT,
  Revision INTEGER,
  Domain TEXT,
  Status TEXT,
  Published TEXT
);
```

The `Post` Go model currently includes the same logical fields with
`Published bool`. `SavePostDataInDB` assigns `Revision` by counting existing
rows for the same `(RequestUri, Domain)` pair before inserting.

### MVP records and fields

Keep `Post` as the page revision record for the first implementation pass, with
additive fields or companion tables only where needed:

| Need | Suggested storage | Notes |
| --- | --- | --- |
| Revision identity | `Post.Id`, `Post.RequestUri`, `Post.Domain`, `Post.Revision` | Add uniqueness on `(Domain, RequestUri, Revision)` when practical. |
| Editor/audit | `OwnerId`, `EditorId`, `Date` | `Date` should be Unix milliseconds or seconds consistently documented in code. |
| Page content | `Body`, `Header` | If bodies become large, store archive path/blob reference in an additive field. |
| Metadata | `Title`, `Tags`, `Status`, `Published` | Normalize `Published` representation across DB backends. |
| Sessions | New `Session` table or signed-cookie-only sessions | Must support logout/expiration; avoid storing raw tokens. |
| Users | New minimal `User`/`Credential` table or config/env-backed single admin | Store password hash only. |
| Freeze state | New `SiteState` key/value table | Records frozen/unfrozen mode and timestamps. |
| Backups | New `Backup` table | Stores archive path, created timestamp, checksum, status, and error if failed. |
| Navigation | New `PageMeta` or additive `ParentUri`/`SortOrder` fields | Keep simple; do not build a full taxonomy engine yet. |

Avoid destructive migrations during this MVP. Prefer creating missing tables and
adding nullable fields with safe defaults.

## Security requirements

- **Path traversal:** all read, write, revision, backup, and restore paths must
  pass containment checks. Current request handling does not perform these
  checks yet and must be treated as vulnerable until the route-hardening phase
  lands.
- **Authentication:** all actions other than static serving and login require an
  authenticated operator. Current authentication is a placeholder that always
  succeeds; no session, password, or cookie validation exists yet.
- **Sessions:** cookies must be HTTP-only, time-limited, and invalidated on
  logout. Use `Secure` when served over HTTPS.
- **CSRF:** every mutating action (`POST ?edit`, `?delete`, `?properties`,
  `?subpages`, `?freeze`, `?unfreeze`, `?backup`, profile updates, restore)
  requires CSRF validation.
- **Credential leakage:** never log passwords, session tokens, CSRF tokens, or
  full PostgreSQL DSNs containing `PG_PASS`.
- **Backup/restore:** backups must not be written into public paths by default;
  restore must validate archive contents before extraction.
- **Error handling:** external responses should be generic; detailed filesystem
  or database errors belong in protected logs.

## Validation plan for later phases

Baseline validation for every change:

```sh
# In the Copilot agent environment, follow .github/copilot-instructions.md
# for the local Go toolchain path before running Go commands.
go test ./...
go build ./...
git diff --check
```

Additional validation expected as implementation proceeds:

- Unit tests for config defaults, `DBFullFilePath`, route/action parsing, path
  containment, index-file resolution, and atomic write helpers.
- Database tests for table creation, revision numbering, watchdog updates, and
  save errors for embedded backends.
- HTTP `httptest` coverage for each action in the contract, including
  unauthenticated, authenticated, CSRF-failure, and unsafe-path cases.
- Runtime checks with a small fixture site:
  1. start SiteBrush with `-web-path` pointing to the fixture,
  2. browse `/`,
  3. log in,
  4. edit/save a page,
  5. inspect revisions,
  6. freeze/unfreeze,
  7. create a backup,
  8. log out and verify private actions are blocked.
- Browser or WebView smoke check for GUI builds on platforms with WebView
  dependencies installed.
