---
title: SiteBrush v1 Compatibility Matrix
status: internal
---

# SiteBrush v1 Compatibility Matrix

This matrix tracks the selected full legacy PHP/MySQL product parity conversion
from SiteBrush v1 into Go v2. The selected parity target includes multi-domain
hosting, media uploads, CKEditor editing, templates and repeating elements,
grab/import, groups, account recovery, and backup/export.

The implementation model is one branch and one final PR. Status values below
describe the current Go v2 branch and the planned target for parity.

## Source references

| Area | v1 source | v2 source |
| --- | --- | --- |
| Product promises | `sitebrush-v1/README.md` | `sitebrush-v2/README.md`, `sitebrush-v2/docs/mvp-scope-and-contracts.md` |
| Dispatch | `sitebrush-v1/backend/init.php` | `sitebrush-v2/pkg/webserver/functions.go`, `sitebrush-v2/pkg/webserver/webserver.go` |
| Controllers and views | `sitebrush-v1/backend/app/controllers/system/*.php`, `sitebrush-v1/backend/app/views/*.tpl.html` | `sitebrush-v2/pkg/webserver/functions.go` |
| Data model | `sitebrush-v1/sitebrush.sql` | `sitebrush-v2/pkg/data/data.go`, `sitebrush-v2/pkg/database/functions.go` |
| Public assets | `sitebrush-v1/public_html`, `sitebrush-v1/public_html/config.php` | `sitebrush-v2/pkg/config/config.go`, `sitebrush-v2/pkg/webserver/functions.go` |

## 1. Legacy route/action mapping

v1 chooses a system controller from the first GET key when a matching file exists
under `backend/app/controllers/system` (`sitebrush-v1/backend/init.php`). v2
currently parses one empty-valued query action at a time in
`sitebrush-v2/pkg/webserver/functions.go`.

| v1 endpoint/action | v1 file | v2 route/handler target | Status | Notes |
| --- | --- | --- | --- | --- |
| Static page, no query | `backend/init.php`, `public_html/.htaccess` | `GET /path`, `siteService.handle` -> `http.ServeFile` | Current | v2 serves from `WEB_FILE_PATH` with path containment checks. |
| `?login` | `controllers/system/login.php`, `views/Login.tpl.html` | `GET,POST /?login`, `siteService.login` | Current, changed | v1 logs in by email/password and PHP session. v2 uses configured admin password env and in-memory session. |
| `?logout` | `controllers/system/logout.php` | `GET,POST /?logout`, `siteService.logout` | Current, changed | v2 requires POST plus CSRF to invalidate the session; GET only renders confirmation. |
| `?edit` | `controllers/system/edit.php`, `views/Wiki*.tpl.html` | `GET,POST /?edit`, `siteService.edit` | Partial | v2 saves static file atomically and records file revisions. CKEditor, template propagation, and DB post records still need parity. |
| `?upload=file` | `controllers/system/upload.php`, `views/Wiki.tpl.html` | `POST /?upload=file`, proposed `siteService.uploadFile` | Planned | Must accept CKEditor file upload, hash content, store metadata, and return CKEditor callback response. |
| `?upload=image` | `controllers/system/upload.php`, `views/Wiki.tpl.html` | `POST /?upload=image`, proposed `siteService.uploadImage` | Planned | Must support small/big image processing options from v1 or document narrower image policy. |
| Upload options | `controllers/system/upload.php` | `GET,POST /?upload-options`, proposed `siteService.uploadOptions` | Planned | v1 stores size/crop/desaturate/sharpen choices in session. |
| `?grab` and `?grab=<url>` | `controllers/system/grab.php`, `views/Grab.tpl.html` | `GET,POST /?grab`, proposed `siteService.grab` | Planned | Must import remote HTML and referenced files, replacing external asset URLs with local `/f` URLs. |
| `?revisions` | `controllers/system/revisions.php`, `views/Revisions.tpl.html` | `GET,POST /?revisions`, `siteService.revisions` | Partial | v2 lists/restores file-backed revisions. Need v1-style authors, status, deleted revisions, and DB linkage. |
| `?delete=<id>` | `controllers/system/delete.php`, `views/Revisions.tpl.html` | `POST /?delete`, `siteService.deleteRevision` | Stub | v2 returns not implemented. Target should soft-delete revision/page metadata, not unsafe GET deletion. |
| `?undelete=<id>` | `controllers/system/undelete.php`, `views/Revisions.tpl.html` | `POST /?undelete`, proposed `siteService.undeleteRevision` | Planned | Restore deleted v1 revision semantics with CSRF-protected POST. |
| `?properties` | `controllers/system/properties.php`, `views/Properties.tpl.html` | `GET,POST /?properties`, `siteService.properties` | Stub | Target needs title, tags, slug rename, redirect/alias creation, subpage URI moves, and cache regeneration. |
| `?subpages` | `controllers/system/subpages.php`, `views/SiteBrushMenu.tpl.html` | `GET,POST /?subpages`, `siteService.subpages` | Partial | v2 lists HTML files. Target needs DB/page-tree parity and editable navigation metadata. |
| `?freeze` | `controllers/system/freeze.php`, `views/SiteBrushMenu.tpl.html` | `POST /?freeze`, `siteService.setFreeze(true)` | Partial, changed | v2 stores archive state. Target must preserve v1 private edit/public static split without GET mutation. |
| `?unfreeze` | `controllers/system/unfreeze.php`, `views/SiteBrushMenu.tpl.html` | `POST /?unfreeze`, `siteService.setFreeze(false)` | Partial | v1 regenerates cache and cleanhtml. v2 must publish frozen edits and rebuild public artifacts. |
| `?backup` | `controllers/system/backup.php`, `libraries/includes/auto/backup.php` | `POST /?backup`, `siteService.backup` | Partial, changed | v1 downloads existing `.tgz` through `/b`. v2 creates a zip outside web root and returns JSON. Add download/export route. |
| `?profile` | `controllers/system/profile.php`, `views/Profile.tpl.html` | `GET,POST /?profile`, `siteService.profile` | Partial | v2 shows session info. Target needs email/password changes and grab preferences. |
| `?recover` and `?recover=<code>` | `controllers/system/recover.php`, `views/RecoverPassword.tpl.html`, `views/ChangePassword.tpl.html` | `GET,POST /?recover`, proposed `siteService.recover` | Planned | Replace v1 email code flow and MD5 password reset with tokenized, expiring recovery. |
| `?join` | `controllers/system/join.php`, `views/Join.tpl.html` | `GET,POST /?join`, proposed `siteService.join` | Planned | Needed for first admin registration and default group creation if config-only admin is not the final parity choice. |
| `?verify` | `controllers/system/verify.php`, `views/Error_Verify_Domain.tpl.html` | `GET,POST /?verify`, proposed `siteService.verifyDomain` | Planned | Needed for multi-domain DNS/email ownership flow. Avoid shelling out to `dig` directly in request handlers. |
| `?domains` | `controllers/system/domains.php` | `GET /?domains`, proposed `siteService.domains` | Planned | Master-domain admin listing of registered domains. |
| `?captcha`, `?captcha.png` | `controllers/system/captcha.php`, `controllers/system/captcha.png.php` | proposed `/captcha` or remove if not needed | Planned | Needed only if join/recover keep captcha. Prefer rate limiting plus optional captcha. |

## 2. Data model mapping

v1 stores core CMS state in MySQL tables from `sitebrush-v1/sitebrush.sql`.
v2 currently creates `Post`, `SiteState`, `Backup`, and `DBWatchDog` tables in
`sitebrush-v2/pkg/database/functions.go`; the Go `Post` struct is in
`sitebrush-v2/pkg/data/data.go`.

| v1 table/fields | Proposed v2 model/table | Status | Migration notes |
| --- | --- | --- | --- |
| `domain`: `id`, `name`, `dnszonedata`, `cnamesecret`, `emailsecret`, `status`, `freezed` | `Domain`: `ID`, `Name`, `DNSZoneData`, `CNAMESecret`, `EmailSecretHash`, `Status`, `Frozen` | Planned | Required for multi-domain. Store secrets hashed where possible and keep unique domain names. |
| `user`: identity, email, `password`, profile, quotas, `autograb`, `domaintograb`, status | `User`, `Credential`, optional `UserPreference` | Planned | Migrate MD5 password values only through forced reset or one-time verifier; never keep MD5 as active auth. |
| `group`: `owner_id`, `name`, `title`, `comment`, `date`, `status`, `domain` | `Group` | Planned | Preserve system groups such as Superuser and public Everyone/User groups. |
| `user_group` | `UserGroup` | Planned | Many-to-many membership. Needed for v1 rights checks currently done by `AmIInGroup`. |
| `invite`, `user_invite` | `Invite`, `UserInvite` | Planned | Needed if invite flow is retained. Add expiry and single-use token fields. |
| `post`: `ownerid`, `deleterid`, `requesturi`, `type`, `date`, `title`, `text`, `shorttext`, `tags`, `version`, `domain`, `status`, `published` | Extend v2 `Post`: `OwnerId`, `EditorId`, `DeleterId`, `RequestUri`, `Type`, `Date`, `Title`, `Body`, `Summary`, `Tags`, `Revision`, `Domain`, `Status`, `Published` | Partial | v2 `Post` has most revision fields but not `Type`, `DeleterId`, or `Summary`. Normalize `version` to `Revision`. |
| `uri`: `olduri`, `newuri`, `date`, `status`, `domain` | `Redirect` or `URIMap` | Planned | Required for v1 no-404 rename behavior from properties controller. |
| `template`: `name`, `data`, `status`, `domain` | `Template` | Planned | Needed for repeating elements from `UpdateFromTemplate`. |
| `post_template` | `PostTemplate` | Planned | Track pages linked to each repeating element/template. |
| `media`: type, hash, originalhash, format, dimensions, status, domain, day/date, sizesarray, rating, views, bytesused | `Media` | Planned | Keep content hash as stable filename. Add MIME type and storage path. |
| `post_media`, `user_media`, `group_media`, `message_media` | join tables with same logical names | Planned | Required for ownership, permissions, and cleanup. |
| `message`: to/from, nickname, order, subject, text, type, unread, status, domain | `Message` | Deferred parity | Include because v1 schema has it, but not in selected core editor flow unless UI requires it. |
| `group_post`, `user_post`, `post_message`, `group_message`, `user_message` | equivalent join tables | Planned/deferred | Implement the joins used by restored UI first; preserve schema for data import. |
| `language`, `domain_language` | `Language`, `DomainLanguage` | Deferred parity | Needed only if legacy multi-language UI is restored. Preserve during import. |
| `propel_migration` | `SchemaMigration` or external migrations table | Planned | Replace Propel with Go migration tracking. |
| v2 `DBWatchDog` | keep or replace with health metadata | Current | Internal v2 table, no v1 import source. |
| v2 `SiteState` | keep, plus domain-scoped freeze state | Partial | Must become domain/site scoped for multi-domain. |
| v2 `Backup` | keep, add domain, format, download token, error details | Partial | Store backup/export metadata for zip/tgz compatibility. |

## 3. Static and asset path mapping

v1 configures per-domain variable paths in `sitebrush-v1/backend/init.php` and
public static folders in `sitebrush-v1/public_html/config.php`. v2 exposes a
single public root with `WEB_FILE_PATH`, `WEB_INDEX_FILE`, and archive storage
under `DB_FILE_PATH/sitebrush-archives/<site-hash>`.

| Legacy path | v1 meaning | v2 target | Status | Notes |
| --- | --- | --- | --- | --- |
| `/p` | Public editor assets from `public_html/p` | Serve bundled editor assets under `/p` or `/sitebrush/assets` | Planned | v1 templates use `StaticFolder` set to `p`. Keep `/p` for compatibility redirects/assets. |
| `/d` | Duplicate/static asset folder in `public_html/d` | Serve as legacy alias or remove after audit | Planned | Exists in v1 tree with CSS, JS, and icons. Map requests safely if old pages reference it. |
| `/f` | Uploaded/grabbed files from `var/storage/<domain>` | `Media` file store, exposed as `/f/<hash>.<ext>` | Planned | Required for CKEditor upload and grab/import. Must block traversal and enforce MIME/size policy. |
| `/b` | Backup download alias used by `X-Accel-Redirect` | Authenticated backup download route, for example `/b/<domain>.tgz` or `/backups/<id>` | Planned, changed | v2 currently writes zip backups outside web root and returns JSON. Add controlled download. |
| `cache/<domain>` | Generated editable/static HTML with SiteBrush link | v2 public `WEB_FILE_PATH` or generated publish output | Planned | v1 `UpdateCache` writes full HTML when not frozen. v2 needs explicit publish/cache model. |
| `cleanhtml/<domain>` | Generated clean public HTML without editor link | v2 published visitor output | Planned | Preserve clean visitor pages if the v2 architecture separates editor chrome from public output. |
| `backup/<domain>.tgz` | Prebuilt archive downloaded through `/b` | `sitebrush-archives/<site-hash>/backups/*.zip` plus optional `.tgz` export | Partial | Keep metadata in `Backup`; support tgz only if legacy imports or external consumers require it. |
| `storage/<domain>` | Uploaded and grabbed static files | `sitebrush-archives/<site-hash>/media` or configured media root | Planned | Should not be mixed with editor internals; public access only through `/f`. |
| `templates_c`, sessions, log | Smarty/session/runtime internals | Go template cache not needed; session store; structured logs | Changed | No PHP/Smarty compiled templates in v2. |

## 4. Intentional security behavior changes

These changes are expected to break some legacy behaviors by design.

| Area | Legacy behavior | v2 parity behavior | Rationale |
| --- | --- | --- | --- |
| Query dispatch | Any matching GET key loads a controller from `controllers/system` | Parse one explicit action only; reject unknown or multi-action queries | Prevent ambiguous privileged dispatch. |
| Mutating actions | Delete, freeze, unfreeze, backup, and logout were often GET links in views | Require POST and CSRF for all mutations | Stop link prefetch, CSRF, and accidental state changes. |
| Authentication | PHP session plus DB user; v1 stores MD5 password hashes in `user.password` | Hashed admin credential or migrated users with modern password hashing | MD5 must not remain an active password verifier. |
| Sessions | PHP session handlers and long-lived `dynamic` cookie | HttpOnly, SameSite session cookie with expiry and logout invalidation | Reduce session theft and stale session risk. |
| File paths | v1 builds cache, backup, and static paths from domain/request values | v2 canonicalizes, unescapes, cleans, and checks containment for every read/write | Prevent traversal, symlink escape, and absolute path injection. |
| Uploads | Extension/hash based storage, CKEditor callback HTML | Validate size, MIME, extension allowlist, image decoding, and safe names | Prevent executable upload and content-type confusion. |
| Grab/import | Server fetches remote URLs and all referenced files | Add URL allowlist/denylist, private-IP blocking, size/time limits, content validation | Prevent SSRF and resource exhaustion. |
| Domain verification | Shells out to `dig` during request flow | Use Go DNS resolver with timeouts and explicit validation | Avoid shell injection and request hangs. |
| Backup/export | `/b` X-Accel download of `.tgz` if present | Authenticated export with archive path outside web root and checksum metadata | Avoid public backup exposure and archive overwrite. |
| Error output | Some v1 flows expose request values and operational details | Generic external errors, detailed protected logs only | Reduce information disclosure. |

## 5. Implementation checkpoints for the one-branch plan

| Checkpoint | Scope | Exit criteria |
| --- | --- | --- |
| 1. Route inventory and dispatcher | Add all selected v1 actions to an explicit v2 action registry | Unknown actions fail closed; all current tests pass. |
| 2. Multi-domain foundation | Domain model, per-domain config, host resolution, domain-scoped state | Static serving, sessions, posts, media, freeze, and backups are domain scoped. |
| 3. Auth, users, groups | User/group tables, first-admin/join flow, login, logout, recovery | Superuser checks replace stub/single-admin assumptions; MD5 migration is safe. |
| 4. Page edit parity | CKEditor-compatible edit UI, save, post DB revisions, delete/undelete, authors | v1 page edit/revision workflows are covered by tests and browser smoke checks. |
| 5. Properties and URI redirects | Rename, title/tags, subpage URI moves, `uri` redirect map | Old URLs redirect or resolve according to v1 no-404 behavior. |
| 6. Templates/repeating elements | Template detection, `PostTemplate` links, propagation to linked pages | Editing a repeated element updates all linked pages predictably. |
| 7. Media upload and `/f` | CKEditor file/image upload, image transforms, media metadata, public serving | Upload callbacks work and unsafe files are rejected. |
| 8. Grab/import | Remote HTML import, recursive asset grab, media records | External pages import with local `/f` assets and SSRF protections. |
| 9. Freeze, publish, cache, cleanhtml | Domain-scoped freeze state, draft/public split, publish rebuild | Visitors see stable public HTML while editors can preview drafts. |
| 10. Backup/export and recovery | Backup creation, download, metadata, restore/import checks | Export is authenticated, checksummed, and restorable in a fixture test. |
| 11. Migration tooling | MySQL v1 import to v2 schema | Fixture import preserves domains, users, groups, posts, media, templates, and redirects. |
| 12. Final validation | Unit, HTTP, migration, browser smoke, `go test ./...`, `go build ./...`, `git diff --check` | Branch is ready for the single final PR review. |
