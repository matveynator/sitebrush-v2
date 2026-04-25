//go:build !darwin || !cgo

package webserver

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	Config "sitebrush/pkg/config"
)

func testConfig(t *testing.T, webRoot string) Config.Settings {
	t.Helper()
	return Config.Settings{
		WEB_FILE_PATH:  webRoot,
		WEB_INDEX_FILE: "index.html",
		DB_FILE_PATH:   filepath.Dir(webRoot),
	}
}

func writeFixtureFile(t *testing.T, root, name, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
}

func TestSafeRequestedFilePathResolvesIndexAndFilesInsideRoot(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)

	tests := []struct {
		name        string
		requestPath string
		wantRel     string
	}{
		{name: "root index", requestPath: "/", wantRel: "index.html"},
		{name: "empty path index", requestPath: "", wantRel: "index.html"},
		{name: "directory index", requestPath: "/docs/", wantRel: "docs/index.html"},
		{name: "file path", requestPath: "/assets/site.css", wantRel: "assets/site.css"},
		{name: "clean dot segments inside root", requestPath: "/docs/./index.html", wantRel: "docs/index.html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := safeRequestedFilePath(cfg, tt.requestPath)
			if err != nil {
				t.Fatalf("safeRequestedFilePath() unexpected error: %v", err)
			}
			want := filepath.Join(root, filepath.FromSlash(tt.wantRel))
			if got != want {
				t.Fatalf("safeRequestedFilePath() = %q, want %q", got, want)
			}
		})
	}
}

func TestSafeRequestedFilePathRejectsTraversalAndAbsoluteEscapes(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)

	unsafePaths := []string{
		"/../secret.txt",
		"/%2e%2e/secret.txt",
		"/docs/%2e%2e/%2e%2e/secret.txt",
		"//etc/passwd",
		"/C:/Windows/win.ini",
		"/docs/..%2f..%2fsecret.txt",
	}

	for _, requestPath := range unsafePaths {
		t.Run(requestPath, func(t *testing.T) {
			if got, err := safeRequestedFilePath(cfg, requestPath); err == nil {
				t.Fatalf("safeRequestedFilePath(%q) = %q, nil error; want rejection", requestPath, got)
			}
		})
	}
}

func TestSafeRequestedFilePathRejectsExistingSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on many Windows environments")
	}

	root := t.TempDir()
	outside := t.TempDir()
	writeFixtureFile(t, outside, "secret.txt", "do not serve")
	linkPath := filepath.Join(root, "leaked.txt")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), linkPath); err != nil {
		t.Skipf("cannot create symlink in this environment: %v", err)
	}

	cfg := testConfig(t, root)
	if got, err := safeRequestedFilePath(cfg, "/leaked.txt"); err == nil {
		t.Fatalf("safeRequestedFilePath() = %q, nil error; want symlink escape rejection", got)
	}
}

func TestHandleRequestServesStaticFilesWithHTTPTest(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "index.html", "home page")
	writeFixtureFile(t, root, "docs/index.html", "docs page")
	writeFixtureFile(t, root, "assets/site.css", "body { color: red; }")
	cfg := testConfig(t, root)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
		wantBody   string
	}{
		{name: "GET root index", method: http.MethodGet, path: "/", wantStatus: http.StatusOK, wantBody: "home page"},
		{name: "GET directory index", method: http.MethodGet, path: "/docs/", wantStatus: http.StatusOK, wantBody: "docs page"},
		{name: "GET static asset", method: http.MethodGet, path: "/assets/site.css", wantStatus: http.StatusOK, wantBody: "body { color: red; }"},
		{name: "HEAD static asset", method: http.MethodHead, path: "/assets/site.css", wantStatus: http.StatusOK, wantBody: ""},
		{name: "missing file", method: http.MethodGet, path: "/missing.html", wantStatus: http.StatusNotFound, wantBody: "Not Found"},
		{name: "unsafe traversal", method: http.MethodGet, path: "/%2e%2e/secret.txt", wantStatus: http.StatusForbidden, wantBody: "Forbidden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			handleRequest(cfg, rec, req)

			res := rec.Result()
			defer res.Body.Close()
			if res.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.wantStatus)
			}
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if tt.wantBody != "" && !strings.Contains(string(body), tt.wantBody) {
				t.Fatalf("body = %q, want substring %q", string(body), tt.wantBody)
			}
			if tt.wantBody == "" && len(body) != 0 {
				t.Fatalf("body = %q, want empty body", string(body))
			}
		})
	}
}

func TestHandleRequestRejectsUnknownPrivilegedQuery(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "index.html", "home page")
	cfg := testConfig(t, root)

	req := httptest.NewRequest(http.MethodGet, "/?edit=1", nil)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusNotFound)
	}
}

func TestHandleRequestPrivateActionsRequireAuth(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "index.html", "home page")
	cfg := testConfig(t, root)

	if checkUserLoggedIn(httptest.NewRequest(http.MethodGet, "/?edit", nil)) {
		t.Fatalf("checkUserLoggedIn() = true without session; want false")
	}

	privateActions := []string{"edit", "delete", "revisions", "subpages", "properties", "freeze", "unfreeze", "backup", "profile", "logout"}
	for _, action := range privateActions {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/?"+action, nil)
			rec := httptest.NewRecorder()

			handleRequest(cfg, rec, req)

			if rec.Result().StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func TestLoginSessionLogoutFlow(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)

	profileReq := httptest.NewRequest(http.MethodGet, "/?profile", nil)
	profileReq.AddCookie(cookie)
	profileRec := httptest.NewRecorder()
	handleRequest(cfg, profileRec, profileReq)
	if profileRec.Result().StatusCode != http.StatusOK {
		t.Fatalf("profile status = %d, want %d", profileRec.Result().StatusCode, http.StatusOK)
	}

	logoutForm := url.Values{"csrf": {csrf}}
	logoutReq := httptest.NewRequest(http.MethodPost, "/?logout", strings.NewReader(logoutForm.Encode()))
	logoutReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutReq.AddCookie(cookie)
	logoutRec := httptest.NewRecorder()
	handleRequest(cfg, logoutRec, logoutReq)
	if logoutRec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want %d", logoutRec.Result().StatusCode, http.StatusSeeOther)
	}

	profileAfterLogoutReq := httptest.NewRequest(http.MethodGet, "/?profile", nil)
	profileAfterLogoutReq.AddCookie(cookie)
	profileAfterLogoutRec := httptest.NewRecorder()
	handleRequest(cfg, profileAfterLogoutRec, profileAfterLogoutReq)
	if profileAfterLogoutRec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("profile after logout status = %d, want %d", profileAfterLogoutRec.Result().StatusCode, http.StatusUnauthorized)
	}
}

func TestEditPostRequiresCSRFAndDoesNotModifyFile(t *testing.T) {
	cfg, cookie, _ := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "index.html", "original")

	form := url.Values{"content": {"changed"}}
	req := httptest.NewRequest(http.MethodPost, "/?edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusForbidden)
	}
	data, err := os.ReadFile(filepath.Join(cfg.WEB_FILE_PATH, "index.html"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	if string(data) != "original" {
		t.Fatalf("file content = %q, want original", string(data))
	}
}

func TestEditPostSavesAtomicallyAndCreatesRevision(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "index.html", "original")

	form := url.Values{"content": {"changed"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/?edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	data, err := os.ReadFile(filepath.Join(cfg.WEB_FILE_PATH, "index.html"))
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if string(data) != "changed" {
		t.Fatalf("file content = %q, want changed", string(data))
	}

	revisionsReq := httptest.NewRequest(http.MethodGet, "/?revisions", nil)
	revisionsReq.AddCookie(cookie)
	revisionsRec := httptest.NewRecorder()
	handleRequest(cfg, revisionsRec, revisionsReq)
	body, err := io.ReadAll(revisionsRec.Result().Body)
	if err != nil {
		t.Fatalf("read revisions body: %v", err)
	}
	if revisionsRec.Result().StatusCode != http.StatusOK || !strings.Contains(string(body), "Revision 1") {
		t.Fatalf("revisions status/body = %d/%q, want Revision 1", revisionsRec.Result().StatusCode, string(body))
	}
}

func TestFreezeAndBackupPersistOutsideWebRoot(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	cfg.DB_TYPE = "sqlite"
	cfg.DB_FULL_FILE_PATH = filepath.Join(t.TempDir(), "sitebrush.db")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "index.html", "home page")

	freezeForm := url.Values{"csrf": {csrf}}
	freezeReq := httptest.NewRequest(http.MethodPost, "/?freeze", strings.NewReader(freezeForm.Encode()))
	freezeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	freezeReq.AddCookie(cookie)
	freezeRec := httptest.NewRecorder()
	handleRequest(cfg, freezeRec, freezeReq)
	if freezeRec.Result().StatusCode != http.StatusOK {
		t.Fatalf("freeze status = %d, want %d", freezeRec.Result().StatusCode, http.StatusOK)
	}
	stateData, err := os.ReadFile(filepath.Join(cfg.DB_FILE_PATH, "sitebrush-archives", siteHash(cfg.WEB_FILE_PATH), "site-state.json"))
	if err != nil {
		t.Fatalf("read site state: %v", err)
	}
	if !strings.Contains(string(stateData), `"frozen": true`) {
		t.Fatalf("site state = %q, want frozen true", string(stateData))
	}

	backupForm := url.Values{"csrf": {csrf}}
	backupReq := httptest.NewRequest(http.MethodPost, "/?backup", strings.NewReader(backupForm.Encode()))
	backupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	backupReq.AddCookie(cookie)
	backupRec := httptest.NewRecorder()
	handleRequest(cfg, backupRec, backupReq)
	if backupRec.Result().StatusCode != http.StatusOK {
		t.Fatalf("backup status = %d, want %d", backupRec.Result().StatusCode, http.StatusOK)
	}
	var record backupRecord
	if err := json.NewDecoder(backupRec.Result().Body).Decode(&record); err != nil {
		t.Fatalf("decode backup response: %v", err)
	}
	if record.Path == "" || record.Checksum == "" {
		t.Fatalf("backup record = %+v, want path and checksum", record)
	}
	if pathIsInsideRoot(cfg.WEB_FILE_PATH, record.Path) {
		t.Fatalf("backup path %q is inside web root %q", record.Path, cfg.WEB_FILE_PATH)
	}
	if _, err := os.Stat(record.Path); err != nil {
		t.Fatalf("stat backup archive: %v", err)
	}

	db, err := sql.Open("sqlite", cfg.DB_FULL_FILE_PATH)
	if err != nil {
		t.Fatalf("open backup db: %v", err)
	}
	defer db.Close()
	var backupCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM Backup WHERE Path = ? AND Checksum = ? AND Status = ?", record.Path, record.Checksum, "complete").Scan(&backupCount); err != nil {
		t.Fatalf("query backup record: %v", err)
	}
	if backupCount != 1 {
		t.Fatalf("backup table records = %d, want 1", backupCount)
	}
}

func loginTestUser(t *testing.T) (Config.Settings, *http.Cookie, string) {
	t.Helper()
	defaultSessions = newSessionStore()
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD", "secret")

	root := t.TempDir()
	cfg := testConfig(t, root)

	form := url.Values{"password": {"secret"}}
	req := httptest.NewRequest(http.MethodPost, "/?login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login did not set a session cookie")
	}
	cookie := cookies[0]
	sessionReq := httptest.NewRequest(http.MethodGet, "/?profile", nil)
	sessionReq.AddCookie(cookie)
	session, ok := defaultSessions.get(sessionReq)
	if !ok {
		t.Fatalf("login cookie did not create a valid session")
	}
	return cfg, cookie, session.CSRFToken
}
