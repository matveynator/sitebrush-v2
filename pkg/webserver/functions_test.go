//go:build !darwin || !cgo

package webserver

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	Config "sitebrush/pkg/config"
	Data "sitebrush/pkg/data"
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

func TestCanonicalHostNormalizesValidHosts(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "domain lowercase", host: "Example.COM", want: "example.com"},
		{name: "domain strips port", host: "Example.COM:2444", want: "example.com"},
		{name: "domain strips trailing dot", host: "Example.COM.", want: "example.com"},
		{name: "localhost with port", host: "localhost:2444", want: "localhost"},
		{name: "ipv4 with port", host: "127.0.0.1:8080", want: "127.0.0.1"},
		{name: "bracketed ipv6 with port", host: "[::1]:2444", want: "::1"},
		{name: "bracketed ipv6 without port", host: "[::1]", want: "::1"},
		{name: "ipv6 without port", host: "2001:db8::1", want: "2001:db8::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalHost(tt.host)
			if err != nil {
				t.Fatalf("canonicalHost(%q) unexpected error: %v", tt.host, err)
			}
			if got != tt.want {
				t.Fatalf("canonicalHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestCanonicalHostRejectsUnsafeHosts(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example"
	longHost := strings.Repeat("a", 254)
	badHosts := []string{
		"",
		" example.com",
		"example.com ",
		"example.com/path",
		`example.com\path`,
		"bad host.example",
		"bad_host.example",
		"example..com",
		"-bad.example",
		"bad-.example",
		"exa$mple.com",
		"example.com:abc",
		"[example.com]",
		"[bad-host.example]",
		"[example.com]:2444",
		"example.com\n",
		longLabel,
		longHost,
	}

	for _, host := range badHosts {
		t.Run(host, func(t *testing.T) {
			if got, err := canonicalHost(host); err == nil {
				t.Fatalf("canonicalHost(%q) = %q, nil error; want rejection", host, got)
			}
		})
	}
}

func TestTrustedDBRevisionDomainUsesDefaultForUntrustedHosts(t *testing.T) {
	t.Setenv("SITEBRUSH_ALLOWED_HOSTS", "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "attacker.example.test"

	domain, trusted := trustedDBRevisionDomain(req)

	if trusted {
		t.Fatal("trustedDBRevisionDomain() trusted unconfigured public host")
	}
	if domain != defaultDBDomain {
		t.Fatalf("domain = %q, want %q", domain, defaultDBDomain)
	}
}

func TestTrustedDBRevisionDomainAllowsConfiguredHostsAndLocalDev(t *testing.T) {
	t.Setenv("SITEBRUSH_ALLOWED_HOSTS", " Example.TEST:2444 ")
	allowedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	allowedReq.Host = "example.test"
	domain, trusted := trustedDBRevisionDomain(allowedReq)
	if !trusted || domain != "example.test" {
		t.Fatalf("allowed domain/trusted = %q/%v, want example.test/true", domain, trusted)
	}

	localReq := httptest.NewRequest(http.MethodGet, "/", nil)
	localReq.Host = "127.0.0.1:2444"
	localReq.RemoteAddr = "127.0.0.1:55244"
	domain, trusted = trustedDBRevisionDomain(localReq)
	if !trusted || domain != "127.0.0.1" {
		t.Fatalf("local domain/trusted = %q/%v, want 127.0.0.1/true", domain, trusted)
	}
}

func TestTrustedDBRevisionDomainRequiresLoopbackRemoteForImplicitLocalDev(t *testing.T) {
	t.Setenv("SITEBRUSH_ALLOWED_HOSTS", "")

	remoteReq := httptest.NewRequest(http.MethodGet, "/", nil)
	remoteReq.Host = "localhost:2444"
	remoteReq.RemoteAddr = "203.0.113.10:55244"
	domain, trusted := trustedDBRevisionDomain(remoteReq)
	if trusted {
		t.Fatal("trustedDBRevisionDomain() trusted localhost host from non-loopback remote")
	}
	if domain != defaultDBDomain {
		t.Fatalf("remote localhost domain = %q, want %q", domain, defaultDBDomain)
	}

	loopbackReq := httptest.NewRequest(http.MethodGet, "/", nil)
	loopbackReq.Host = "localhost:2444"
	loopbackReq.RemoteAddr = "127.0.0.1:55244"
	domain, trusted = trustedDBRevisionDomain(loopbackReq)
	if !trusted || domain != "localhost" {
		t.Fatalf("loopback localhost domain/trusted = %q/%v, want localhost/true", domain, trusted)
	}
}

func TestDomainPathsStayInsideConfiguredRoots(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}

	roots, err := service.domainPaths("Example.COM:2444")
	if err != nil {
		t.Fatalf("domainPaths() unexpected error: %v", err)
	}

	if !pathIsInsideRoot(root, roots.PublicRoot) {
		t.Fatalf("public root %q is outside web root %q", roots.PublicRoot, root)
	}
	archiveRoot := service.archiveRoot()
	for name, path := range map[string]string{
		"archive": roots.ArchiveRoot,
		"cache":   roots.CacheRoot,
		"media":   roots.MediaRoot,
	} {
		if !pathIsInsideRoot(archiveRoot, path) {
			t.Fatalf("%s root %q is outside archive root %q", name, path, archiveRoot)
		}
		if !strings.Contains(path, "example.com") {
			t.Fatalf("%s root %q does not include canonical host", name, path)
		}
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

func TestHandleRequestServesLegacyPAndDStaticAliasesSafely(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "p/editor/app.js", "p asset")
	writeFixtureFile(t, root, "d/theme/site.css", "d asset")
	cfg := testConfig(t, root)

	tests := []struct {
		name       string
		path       string
		wantStatus int
		wantBody   string
	}{
		{name: "p asset", path: "/p/editor/app.js", wantStatus: http.StatusOK, wantBody: "p asset"},
		{name: "d asset", path: "/d/theme/site.css", wantStatus: http.StatusOK, wantBody: "d asset"},
		{name: "missing p asset", path: "/p/missing.js", wantStatus: http.StatusNotFound, wantBody: "Not Found"},
		{name: "p traversal forbidden", path: "/p/%2e%2e/index.html", wantStatus: http.StatusForbidden, wantBody: "Forbidden"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handleRequest(cfg, rec, req)

			if rec.Result().StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Result().StatusCode, tt.wantStatus)
			}
			body, err := io.ReadAll(rec.Result().Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if !strings.Contains(string(body), tt.wantBody) {
				t.Fatalf("body = %q, want substring %q", string(body), tt.wantBody)
			}
		})
	}
}

func TestHandleRequestServesFMediaFromDomainMediaRootOnly(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}
	roots, err := service.domainPaths("media.example.test")
	if err != nil {
		t.Fatalf("domainPaths() unexpected error: %v", err)
	}
	writeFixtureFile(t, roots.MediaRoot, "avatar.png", "domain media")
	writeFixtureFile(t, root, "f/avatar.png", "web root media must not be served")

	req := httptest.NewRequest(http.MethodGet, "/f/avatar.png", nil)
	req.Host = "Media.Example.Test:8080"
	rec := httptest.NewRecorder()
	handleRequest(cfg, rec, req)

	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if rec.Result().StatusCode != http.StatusOK || !strings.Contains(string(body), "domain media") {
		t.Fatalf("status/body = %d/%q, want domain media", rec.Result().StatusCode, string(body))
	}
	if strings.Contains(string(body), "web root media") {
		t.Fatalf("/f served WEB_FILE_PATH media instead of domain media root: %q", string(body))
	}

	missingHostReq := httptest.NewRequest(http.MethodGet, "/f/avatar.png", nil)
	missingHostReq.Host = "other.example.test"
	missingHostRec := httptest.NewRecorder()
	handleRequest(cfg, missingHostRec, missingHostReq)
	if missingHostRec.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("missing host media status = %d, want %d", missingHostRec.Result().StatusCode, http.StatusNotFound)
	}

	traversalReq := httptest.NewRequest(http.MethodGet, "/f/%2e%2e/avatar.png", nil)
	traversalReq.Host = "media.example.test"
	traversalRec := httptest.NewRecorder()
	handleRequest(cfg, traversalRec, traversalReq)
	if traversalRec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("traversal status = %d, want %d", traversalRec.Result().StatusCode, http.StatusForbidden)
	}
}

func TestHandleRequestRejectsUnsafeHostForDomainMedia(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(t, root)

	req := httptest.NewRequest(http.MethodGet, "/f/avatar.png", nil)
	req.Host = "bad_host.example"
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusBadRequest)
	}
}

func TestHandleRequestDoesNotPubliclyServeBackups(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "b/site.zip", "backup data")
	cfg := testConfig(t, root)

	req := httptest.NewRequest(http.MethodGet, "/b/site.zip", nil)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusNotFound)
	}
}

func TestParseActionRecognizesPlannedV1ParityActions(t *testing.T) {
	actions := []string{"join", "verify", "recover", "upload", "grab", "domains", "undelete", "captcha"}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			got, err := parseAction(action)
			if err != nil {
				t.Fatalf("parseAction(%q) unexpected error: %v", action, err)
			}
			if got != action {
				t.Fatalf("parseAction(%q) = %q, want %q", action, got, action)
			}
		})
	}
}

func TestPlannedV1PublicActionsReturnNotImplemented(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "index.html", "home page")
	cfg := testConfig(t, root)

	req := httptest.NewRequest(http.MethodGet, "/?recover", nil)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusNotImplemented)
	}
}

func TestPasswordHashVerifyUsesVersionedSaltedHash(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hashPassword() error = %v", err)
	}
	if !strings.HasPrefix(hash, passwordHashAlgorithm+"$v=1$i=") {
		t.Fatalf("hash = %q, want versioned %s hash", hash, passwordHashAlgorithm)
	}
	if strings.Contains(hash, "correct") || strings.Contains(strings.ToLower(hash), "md5") {
		t.Fatalf("hash leaks plaintext or legacy algorithm marker: %q", hash)
	}
	ok, err := verifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("verifyPassword(correct) error = %v", err)
	}
	if !ok {
		t.Fatalf("verifyPassword(correct) = false, want true")
	}
	ok, err = verifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("verifyPassword(wrong) error = %v", err)
	}
	if ok {
		t.Fatalf("verifyPassword(wrong) = true, want false")
	}
	if ok, err := verifyPassword("anything", "md5:legacy"); err == nil || ok {
		t.Fatalf("verifyPassword(legacy) = %v, %v; want unsupported error", ok, err)
	}
}

func TestPasswordHashVerifyRejectsExcessiveIterations(t *testing.T) {
	corrupted := passwordHashAlgorithm + "$v=1$i=600001$s=ignored$h=ignored"
	if ok, err := verifyPassword("anything", corrupted); err == nil || ok {
		t.Fatalf("verifyPassword(excessive iterations) = %v, %v; want iteration cap error", ok, err)
	}
}

func TestFirstJoinCreatesPersistentSuperuserAdmin(t *testing.T) {
	defaultSessions = newSessionStore()
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD", "")
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD_SHA256", "")
	root := t.TempDir()
	cfg := testConfig(t, root)

	getReq := httptest.NewRequest(http.MethodGet, "/?join", nil)
	getRec := httptest.NewRecorder()
	handleRequest(cfg, getRec, getReq)
	if getRec.Result().StatusCode != http.StatusOK {
		t.Fatalf("join GET status = %d, want %d", getRec.Result().StatusCode, http.StatusOK)
	}

	form := url.Values{"email": {"Admin@Example.test"}, "password": {"admin-password-1"}}
	req := httptest.NewRequest(http.MethodPost, "/?join", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handleRequest(cfg, rec, req)
	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("join POST status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatalf("join did not set a persistent session cookie")
	}

	service := siteService{config: cfg, sessions: defaultSessions}
	store, err := service.loadAuthStore()
	if err != nil {
		t.Fatalf("load auth store: %v", err)
	}
	if len(store.Users) != 1 || store.Users[0].Email != "admin@example.test" {
		t.Fatalf("users = %+v, want one normalized admin", store.Users)
	}
	if store.Users[0].PasswordHash == "" || strings.Contains(store.Users[0].PasswordHash, "admin-password-1") {
		t.Fatalf("stored password hash is missing or unsafe: %q", store.Users[0].PasswordHash)
	}
	if len(store.Groups) != 1 || store.Groups[0].Name != superuserGroupName {
		t.Fatalf("groups = %+v, want %s", store.Groups, superuserGroupName)
	}
	if len(store.UserGroups) != 1 || store.UserGroups[0].UserId != store.Users[0].Id || store.UserGroups[0].GroupId != store.Groups[0].Id {
		t.Fatalf("user groups = %+v, want first admin in superuser group", store.UserGroups)
	}
	authDirInfo, err := os.Stat(filepath.Dir(service.authStorePath()))
	if err != nil {
		t.Fatalf("stat auth store dir: %v", err)
	}
	if authDirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("auth store dir mode = %o, want 0700", authDirInfo.Mode().Perm())
	}
}

func TestDuplicateJoinBlockedAfterPersistentUserExists(t *testing.T) {
	defaultSessions = newSessionStore()
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}
	if _, err := service.createFirstAdmin("admin@example.test", "admin-password-1"); err != nil {
		t.Fatalf("create first admin: %v", err)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/?join", nil)
	getRec := httptest.NewRecorder()
	handleRequest(cfg, getRec, getReq)
	if getRec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("duplicate join GET status = %d, want %d", getRec.Result().StatusCode, http.StatusForbidden)
	}

	form := url.Values{"email": {"other@example.test"}, "password": {"admin-password-2"}}
	postReq := httptest.NewRequest(http.MethodPost, "/?join", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRec := httptest.NewRecorder()
	handleRequest(cfg, postRec, postReq)
	if postRec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("duplicate join POST status = %d, want %d", postRec.Result().StatusCode, http.StatusForbidden)
	}
}

func TestConcurrentFirstAdminCreateAllowsExactlyOneAdmin(t *testing.T) {
	defaultSessions = newSessionStore()
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}

	const attempts = 12
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := service.createFirstAdmin("admin@example.test", "admin-password-1")
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful first-admin creates = %d, want 1", successes)
	}

	store, err := service.loadAuthStore()
	if err != nil {
		t.Fatalf("load auth store: %v", err)
	}
	if len(store.Users) != 1 || len(store.Groups) != 1 || len(store.UserGroups) != 1 {
		t.Fatalf("store = %+v, want exactly one persisted user/admin membership", store)
	}
	if len(activeUsers(store.Users)) != 1 || store.Users[0].Email != "admin@example.test" {
		t.Fatalf("users = %+v, want exactly one active persisted admin", store.Users)
	}
}

func TestConcurrentFirstAdminJoinAllowsExactlyOneAdmin(t *testing.T) {
	defaultSessions = newSessionStore()
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD", "")
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD_SHA256", "")
	root := t.TempDir()
	cfg := testConfig(t, root)

	const attempts = 12
	start := make(chan struct{})
	results := make(chan int, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			form := url.Values{"email": {"admin@example.test"}, "password": {"admin-password-1"}}
			req := httptest.NewRequest(http.MethodPost, "/?join", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			handleRequest(cfg, rec, req)
			results <- rec.Result().StatusCode
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for status := range results {
		if status == http.StatusSeeOther {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful first-admin joins = %d, want 1", successes)
	}

	service := siteService{config: cfg, sessions: defaultSessions}
	store, err := service.loadAuthStore()
	if err != nil {
		t.Fatalf("load auth store: %v", err)
	}
	if len(store.Users) != 1 || len(store.Groups) != 1 || len(store.UserGroups) != 1 {
		t.Fatalf("store = %+v, want exactly one persisted user/admin membership", store)
	}
}

func TestLoginWithPersistentAdmin(t *testing.T) {
	cfg, cookie, _, session := loginPersistentTestUser(t, "admin-password-1")
	if session.AuthSource != "persistent" || session.Email != "admin@example.test" || session.UserID == 0 {
		t.Fatalf("session = %+v, want persistent admin session", session)
	}

	profileReq := httptest.NewRequest(http.MethodGet, "/?profile", nil)
	profileReq.AddCookie(cookie)
	profileRec := httptest.NewRecorder()
	handleRequest(cfg, profileRec, profileReq)
	body, err := io.ReadAll(profileRec.Result().Body)
	if err != nil {
		t.Fatalf("read profile body: %v", err)
	}
	if profileRec.Result().StatusCode != http.StatusOK || !strings.Contains(string(body), "admin@example.test") {
		t.Fatalf("profile status/body = %d/%q, want persistent user email", profileRec.Result().StatusCode, string(body))
	}
}

func TestPersistentLoginWithEmailDoesNotFallThroughToEnvAdmin(t *testing.T) {
	defaultSessions = newSessionStore()
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD", "env-secret")
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD_SHA256", "")
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}
	if _, err := service.createFirstAdmin("admin@example.test", "persistent-secret"); err != nil {
		t.Fatalf("create first admin: %v", err)
	}

	for _, email := range []string{"admin@example.test", "other@example.test"} {
		t.Run(email, func(t *testing.T) {
			form := url.Values{"email": {email}, "password": {"env-secret"}}
			req := httptest.NewRequest(http.MethodPost, "/?login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			handleRequest(cfg, rec, req)

			if rec.Result().StatusCode != http.StatusUnauthorized {
				t.Fatalf("login status = %d, want %d", rec.Result().StatusCode, http.StatusUnauthorized)
			}
			if cookies := rec.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("login set cookies %+v; want none", cookies)
			}
		})
	}
}

func TestEnvAdminFallbackWithPersistentUsersRequiresOmittedEmail(t *testing.T) {
	defaultSessions = newSessionStore()
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD", "env-secret")
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD_SHA256", "")
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}
	if _, err := service.createFirstAdmin("admin@example.test", "persistent-secret"); err != nil {
		t.Fatalf("create first admin: %v", err)
	}

	form := url.Values{"password": {"env-secret"}}
	req := httptest.NewRequest(http.MethodPost, "/?login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("login status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("env fallback did not set a session cookie")
	}
	sessionReq := httptest.NewRequest(http.MethodGet, "/?profile", nil)
	sessionReq.AddCookie(cookies[0])
	session, ok := defaultSessions.get(sessionReq)
	if !ok {
		t.Fatalf("env fallback cookie did not create a valid session")
	}
	if session.AuthSource != "env" || session.User != "admin" {
		t.Fatalf("session = %+v, want env admin compatibility session", session)
	}
}

func TestProfilePasswordChangeRequiresCSRF(t *testing.T) {
	cfg, cookie, csrf, _ := loginPersistentTestUser(t, "admin-password-1")

	noCSRFForm := url.Values{"current_password": {"admin-password-1"}, "new_password": {"admin-password-2"}}
	noCSRFReq := httptest.NewRequest(http.MethodPost, "/?profile", strings.NewReader(noCSRFForm.Encode()))
	noCSRFReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noCSRFReq.AddCookie(cookie)
	noCSRFRec := httptest.NewRecorder()
	handleRequest(cfg, noCSRFRec, noCSRFReq)
	if noCSRFRec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("profile change without CSRF status = %d, want %d", noCSRFRec.Result().StatusCode, http.StatusForbidden)
	}

	form := url.Values{"csrf": {csrf}, "current_password": {"admin-password-1"}, "new_password": {"admin-password-2"}}
	req := httptest.NewRequest(http.MethodPost, "/?profile", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handleRequest(cfg, rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("profile change status = %d, want %d", rec.Result().StatusCode, http.StatusOK)
	}

	oldLoginForm := url.Values{"email": {"admin@example.test"}, "password": {"admin-password-1"}}
	oldLoginReq := httptest.NewRequest(http.MethodPost, "/?login", strings.NewReader(oldLoginForm.Encode()))
	oldLoginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	oldLoginRec := httptest.NewRecorder()
	handleRequest(cfg, oldLoginRec, oldLoginReq)
	if oldLoginRec.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password login status = %d, want %d", oldLoginRec.Result().StatusCode, http.StatusUnauthorized)
	}

	newLoginForm := url.Values{"email": {"admin@example.test"}, "password": {"admin-password-2"}}
	newLoginReq := httptest.NewRequest(http.MethodPost, "/?login", strings.NewReader(newLoginForm.Encode()))
	newLoginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	newLoginRec := httptest.NewRecorder()
	handleRequest(cfg, newLoginRec, newLoginReq)
	if newLoginRec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("new password login status = %d, want %d", newLoginRec.Result().StatusCode, http.StatusSeeOther)
	}
}

func TestRecoveryTokenPrimitivesStoreHashedExpiringTokens(t *testing.T) {
	defaultSessions = newSessionStore()
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}
	user, err := service.createFirstAdmin("admin@example.test", "admin-password-1")
	if err != nil {
		t.Fatalf("create first admin: %v", err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour)
	token, err := service.createRecoveryToken(user.Id, expiresAt)
	if err != nil {
		t.Fatalf("create recovery token: %v", err)
	}
	if token == "" {
		t.Fatalf("token is empty")
	}
	store, err := service.loadAuthStore()
	if err != nil {
		t.Fatalf("load auth store: %v", err)
	}
	if len(store.RecoveryTokens) != 1 {
		t.Fatalf("recovery tokens = %+v, want one token", store.RecoveryTokens)
	}
	if store.RecoveryTokens[0].TokenHash == token || strings.Contains(store.RecoveryTokens[0].TokenHash, token) {
		t.Fatalf("stored recovery token is not hashed: %+v", store.RecoveryTokens[0])
	}
	if !service.verifyRecoveryToken(user.Id, token, time.Now().UTC()) {
		t.Fatalf("verifyRecoveryToken(valid) = false, want true")
	}
	if service.verifyRecoveryToken(user.Id, token, time.Now().UTC()) {
		t.Fatalf("verifyRecoveryToken(reused) = true, want false")
	}
	if service.verifyRecoveryToken(user.Id, token, expiresAt.Add(time.Second)) {
		t.Fatalf("verifyRecoveryToken(expired) = true, want false")
	}
}

func TestConcurrentRecoveryTokenVerificationAllowsExactlyOneUse(t *testing.T) {
	defaultSessions = newSessionStore()
	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}
	user, err := service.createFirstAdmin("admin@example.test", "admin-password-1")
	if err != nil {
		t.Fatalf("create first admin: %v", err)
	}
	token, err := service.createRecoveryToken(user.Id, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("create recovery token: %v", err)
	}

	const attempts = 12
	start := make(chan struct{})
	results := make(chan bool, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- service.verifyRecoveryToken(user.Id, token, time.Now().UTC())
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful recovery token verifications = %d, want 1", successes)
	}
}

func TestEnvAdminFallbackStillWorksWhenNoPersistentUsersExist(t *testing.T) {
	cfg, cookie, _ := loginTestUser(t)
	sessionReq := httptest.NewRequest(http.MethodGet, "/?profile", nil)
	sessionReq.AddCookie(cookie)
	session, ok := defaultSessions.get(sessionReq)
	if !ok {
		t.Fatalf("env login did not create session")
	}
	if session.AuthSource != "env" || session.User != "admin" || session.UserID != 0 {
		t.Fatalf("session = %+v, want env admin fallback session", session)
	}

	service := siteService{config: cfg, sessions: defaultSessions}
	hasUsers, err := service.hasPersistentUsers()
	if err != nil {
		t.Fatalf("hasPersistentUsers() error = %v", err)
	}
	if hasUsers {
		t.Fatalf("hasPersistentUsers() = true, want false for env-only login")
	}
}

func TestPlannedV1MutationActionsRequireAuth(t *testing.T) {
	root := t.TempDir()
	writeFixtureFile(t, root, "index.html", "home page")
	cfg := testConfig(t, root)

	for _, action := range []string{"upload", "grab", "domains", "undelete"} {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/?"+action, nil)
			rec := httptest.NewRecorder()

			handleRequest(cfg, rec, req)

			if rec.Result().StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusUnauthorized)
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

func TestEditPostSavesDatabaseBackedPostRevisionWhenConfigured(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	t.Setenv("SITEBRUSH_ALLOWED_HOSTS", "example.test")
	cfg.DB_TYPE = "sqlite"
	cfg.DB_FULL_FILE_PATH = filepath.Join(t.TempDir(), "sitebrush.db")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	form := url.Values{"content": {"changed in db"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/docs/page.html?edit", strings.NewReader(form.Encode()))
	req.Host = "Example.TEST:2444"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}

	db, err := sql.Open("sqlite", cfg.DB_FULL_FILE_PATH)
	if err != nil {
		t.Fatalf("open edit db: %v", err)
	}
	defer db.Close()

	var requestURI, domain, body, status, postType string
	var revision int
	var published bool
	if err := db.QueryRow(`SELECT RequestUri, Domain, Body, Status, Published, Revision, Type
		FROM Post
		WHERE RequestUri = ? AND Domain = ?`, "/docs/page.html", "example.test").Scan(&requestURI, &domain, &body, &status, &published, &revision, &postType); err != nil {
		t.Fatalf("query saved post revision: %v", err)
	}
	if requestURI != "/docs/page.html" || domain != "example.test" || body != "changed in db" {
		t.Fatalf("saved post content = uri:%q domain:%q body:%q", requestURI, domain, body)
	}
	if status != "active" || !published || revision != 1 || postType != "Wiki" {
		t.Fatalf("saved post metadata status=%q published=%v revision=%d type=%q, want active true 1 Wiki", status, published, revision, postType)
	}

	revisionsReq := httptest.NewRequest(http.MethodGet, "/docs/page.html?revisions", nil)
	revisionsReq.Host = "Example.TEST:2444"
	revisionsReq.AddCookie(cookie)
	revisionsRec := httptest.NewRecorder()
	handleRequest(cfg, revisionsRec, revisionsReq)
	bodyBytes, err := io.ReadAll(revisionsRec.Result().Body)
	if err != nil {
		t.Fatalf("read revisions body: %v", err)
	}
	if revisionsRec.Result().StatusCode != http.StatusOK || !strings.Contains(string(bodyBytes), "Database-backed revisions") || !strings.Contains(string(bodyBytes), "DB Revision 1 active published") {
		t.Fatalf("revisions status/body = %d/%q, want DB revision metadata", revisionsRec.Result().StatusCode, string(bodyBytes))
	}
}

func TestEditPostSurfacesDatabaseWriteFailureAfterFileSave(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	cfg.DB_TYPE = "sqlite"
	cfg.DB_FULL_FILE_PATH = filepath.Join(t.TempDir(), "missing-parent", "sitebrush.db")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "index.html", "original")

	form := url.Values{"content": {"changed before db failure"}, "csrf": {csrf}}
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
	if string(data) != "changed before db failure" {
		t.Fatalf("file content = %q, want changed before db failure", string(data))
	}
	if _, err := os.Stat(cfg.DB_FULL_FILE_PATH); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("db path stat error = %v, want not exist", err)
	}
	service := siteService{config: cfg, sessions: defaultSessions}
	records, err := service.loadRevisions("/")
	if err != nil {
		t.Fatalf("load revisions after db failure: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("revision records = %d, want 1", len(records))
	}
	if !strings.Contains(records[0].DBRevisionWarning, "database post revision was not saved") {
		t.Fatalf("DBRevisionWarning = %q, want database warning marker", records[0].DBRevisionWarning)
	}
}

func TestEditPostUsesDefaultDomainForUntrustedDBRevisionHost(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	t.Setenv("SITEBRUSH_ALLOWED_HOSTS", "")
	cfg.DB_TYPE = "sqlite"
	cfg.DB_FULL_FILE_PATH = filepath.Join(t.TempDir(), "sitebrush.db")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "index.html", "original")

	form := url.Values{"content": {"changed with untrusted host"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/?edit", strings.NewReader(form.Encode()))
	req.Host = "attacker.example.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	db, err := sql.Open("sqlite", cfg.DB_FULL_FILE_PATH)
	if err != nil {
		t.Fatalf("open edit db: %v", err)
	}
	defer db.Close()
	var domain string
	if err := db.QueryRow("SELECT Domain FROM Post WHERE RequestUri = ?", "/").Scan(&domain); err != nil {
		t.Fatalf("query saved domain: %v", err)
	}
	if domain != defaultDBDomain {
		t.Fatalf("saved domain = %q, want %q", domain, defaultDBDomain)
	}
}

func TestEditPostNormalizesEncodedPathForDBAndJSONRevisions(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	cfg.DB_TYPE = "sqlite"
	cfg.DB_FULL_FILE_PATH = filepath.Join(t.TempDir(), "sitebrush.db")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	form := url.Values{"content": {"changed via encoded path"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/docs/%70age.html?edit", strings.NewReader(form.Encode()))
	req.Host = "localhost:2444"
	req.RemoteAddr = "127.0.0.1:55244"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	db, err := sql.Open("sqlite", cfg.DB_FULL_FILE_PATH)
	if err != nil {
		t.Fatalf("open edit db: %v", err)
	}
	defer db.Close()
	var requestURI string
	if err := db.QueryRow("SELECT RequestUri FROM Post WHERE Domain = ?", "localhost").Scan(&requestURI); err != nil {
		t.Fatalf("query saved request uri: %v", err)
	}
	if requestURI != "/docs/page.html" {
		t.Fatalf("saved request uri = %q, want /docs/page.html", requestURI)
	}

	service := siteService{config: cfg, sessions: defaultSessions}
	records, err := service.loadRevisions("/docs/page.html")
	if err != nil {
		t.Fatalf("load canonical revisions: %v", err)
	}
	if len(records) != 1 || records[0].RequestURI != "/docs/page.html" {
		t.Fatalf("canonical revision records = %+v, want one /docs/page.html record", records)
	}
	aliasRecords, err := service.loadRevisions("/docs/%70age.html")
	if err != nil {
		t.Fatalf("load alias revisions: %v", err)
	}
	if len(aliasRecords) != 0 {
		t.Fatalf("alias revision records = %+v, want none", aliasRecords)
	}
}

func TestPropertiesPostRequiresCSRFAndDoesNotRenameFile(t *testing.T) {
	cfg, cookie, _ := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	form := url.Values{"new_path": {"/docs/renamed.html"}, "title": {"Renamed"}}
	req := httptest.NewRequest(http.MethodPost, "/docs/page.html?properties", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusForbidden)
	}
	if _, err := os.Stat(filepath.Join(cfg.WEB_FILE_PATH, "docs/page.html")); err != nil {
		t.Fatalf("original file stat: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.WEB_FILE_PATH, "docs/renamed.html")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("renamed file stat error = %v, want not exist", err)
	}
}

func TestPropertiesSafeRenamePersistsMetadataAndRedirects(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	t.Setenv("SITEBRUSH_ALLOWED_HOSTS", "example.com")
	cfg.DB_TYPE = "sqlite"
	cfg.DB_FULL_FILE_PATH = filepath.Join(t.TempDir(), "sitebrush.db")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	form := url.Values{
		"csrf":      {csrf},
		"new_path":  {"/docs/renamed.html"},
		"title":     {"Renamed Title"},
		"tags":      {"alpha, beta"},
		"status":    {"active"},
		"published": {"1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/docs/page.html?properties", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	if _, err := os.Stat(filepath.Join(cfg.WEB_FILE_PATH, "docs/page.html")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old file stat error = %v, want not exist", err)
	}
	data, err := os.ReadFile(filepath.Join(cfg.WEB_FILE_PATH, "docs/renamed.html"))
	if err != nil {
		t.Fatalf("read renamed file: %v", err)
	}
	if string(data) != "original" {
		t.Fatalf("renamed file content = %q, want original", string(data))
	}

	service := siteService{config: cfg, sessions: defaultSessions}
	metadata, err := service.loadSidecarMetadata("/docs/renamed.html")
	if err != nil {
		t.Fatalf("load metadata: %v", err)
	}
	if metadata.Title != "Renamed Title" || metadata.Tags != "alpha, beta" || metadata.Status != "active" || !metadata.Published {
		t.Fatalf("metadata = %+v, want title/tags/status/published persisted", metadata)
	}

	db, err := sql.Open("sqlite", cfg.DB_FULL_FILE_PATH)
	if err != nil {
		t.Fatalf("open redirect db: %v", err)
	}
	defer db.Close()
	var newURI, domain string
	if err := db.QueryRow("SELECT NewUri, Domain FROM Redirect WHERE OldUri = ?", "/docs/page.html").Scan(&newURI, &domain); err != nil {
		t.Fatalf("query redirect: %v", err)
	}
	if newURI != "/docs/renamed.html" || domain != "example.com" {
		t.Fatalf("db redirect newURI/domain = %q/%q, want /docs/renamed.html/example.com", newURI, domain)
	}

	oldReq := httptest.NewRequest(http.MethodGet, "/docs/page.html", nil)
	oldRec := httptest.NewRecorder()
	handleRequest(cfg, oldRec, oldReq)
	if oldRec.Result().StatusCode != http.StatusMovedPermanently {
		t.Fatalf("old path status = %d, want %d", oldRec.Result().StatusCode, http.StatusMovedPermanently)
	}
	if location := oldRec.Result().Header.Get("Location"); location != "/docs/renamed.html" {
		t.Fatalf("redirect Location = %q, want /docs/renamed.html", location)
	}

	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "new old-path content")
	reusedReq := httptest.NewRequest(http.MethodGet, "/docs/page.html", nil)
	reusedRec := httptest.NewRecorder()
	handleRequest(cfg, reusedRec, reusedReq)
	reusedBody, err := io.ReadAll(reusedRec.Result().Body)
	if err != nil {
		t.Fatalf("read reused path body: %v", err)
	}
	if reusedRec.Result().StatusCode != http.StatusOK || !strings.Contains(string(reusedBody), "new old-path content") {
		t.Fatalf("reused path status/body = %d/%q, want static file to shadow old redirect", reusedRec.Result().StatusCode, string(reusedBody))
	}
}

func TestPropertiesRollbackRestoresRedirectsAfterDBRedirectFailure(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	service := siteService{config: cfg, sessions: defaultSessions}
	oldRedirect := Data.Redirect{
		OldUri: "/older.html",
		NewUri: "/still-current.html",
		Date:   123,
		Status: "active",
		Domain: defaultDBDomain,
	}
	if err := service.saveRedirect(oldRedirect); err != nil {
		t.Fatalf("seed old redirect: %v", err)
	}
	originalRedirects, err := os.ReadFile(service.redirectsPath())
	if err != nil {
		t.Fatalf("read seeded redirects: %v", err)
	}
	cfg.DB_TYPE = "sqlite"
	cfg.DB_FULL_FILE_PATH = filepath.Join(t.TempDir(), "missing-parent", "sitebrush.db")
	service = siteService{config: cfg, sessions: defaultSessions}

	form := url.Values{
		"csrf":      {csrf},
		"new_path":  {"/docs/renamed.html"},
		"title":     {"Renamed Title"},
		"status":    {"active"},
		"published": {"1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/docs/page.html?properties", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusInternalServerError)
	}
	oldFileData, err := os.ReadFile(filepath.Join(cfg.WEB_FILE_PATH, "docs/page.html"))
	if err != nil {
		t.Fatalf("old file after rollback: %v", err)
	}
	if string(oldFileData) != "original" {
		t.Fatalf("old file content = %q, want original", string(oldFileData))
	}
	if _, err := os.Stat(filepath.Join(cfg.WEB_FILE_PATH, "docs/renamed.html")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new file stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(service.metadataPath("/docs/renamed.html")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new metadata stat error = %v, want not exist", err)
	}
	currentRedirects, err := os.ReadFile(service.redirectsPath())
	if err != nil {
		t.Fatalf("read redirects after rollback: %v", err)
	}
	if string(currentRedirects) != string(originalRedirects) {
		t.Fatalf("redirects file changed after rollback:\n got %s\nwant %s", currentRedirects, originalRedirects)
	}
	redirects, err := service.loadRedirects()
	if err != nil {
		t.Fatalf("load redirects after rollback: %v", err)
	}
	if len(redirects) != 1 || redirects[0].OldUri != oldRedirect.OldUri || redirects[0].NewUri != oldRedirect.NewUri {
		t.Fatalf("redirects after rollback = %+v, want only old redirect", redirects)
	}
	if _, err := os.Stat(cfg.DB_FULL_FILE_PATH); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("db file stat error = %v, want not exist", err)
	}
}

func TestSafeArchiveNameAvoidsSlashUnderscoreCollisions(t *testing.T) {
	slashed := safeArchiveName("/docs/a_b.html")
	underscored := safeArchiveName("/docs/a/b.html")
	if slashed == underscored {
		t.Fatalf("safeArchiveName collision: both paths produced %q", slashed)
	}
	if !strings.HasPrefix(slashed, "docs_a_b.html-") || !strings.HasPrefix(underscored, "docs_a_b.html-") {
		t.Fatalf("safeArchiveName = %q/%q, want readable prefix plus hash", slashed, underscored)
	}
}

func TestStoredRedirectTargetsMustBeInternalPaths(t *testing.T) {
	tests := []struct {
		name         string
		target       string
		wantStatus   int
		wantLocation string
	}{
		{name: "absolute external URL", target: "https://evil.example", wantStatus: http.StatusNotFound},
		{name: "scheme-relative external URL", target: "//evil.example", wantStatus: http.StatusNotFound},
		{name: "valid internal path", target: "/docs/renamed.html", wantStatus: http.StatusMovedPermanently, wantLocation: "/docs/renamed.html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			cfg := testConfig(t, root)
			service := siteService{config: cfg, sessions: defaultSessions}
			if err := service.saveRedirect(Data.Redirect{
				OldUri: "/docs/page.html",
				NewUri: tt.target,
				Date:   time.Now().UTC().UnixMilli(),
				Status: "active",
				Domain: defaultDBDomain,
			}); err != nil {
				t.Fatalf("save redirect: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/docs/page.html", nil)
			rec := httptest.NewRecorder()
			handleRequest(cfg, rec, req)

			if rec.Result().StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Result().StatusCode, tt.wantStatus)
			}
			if location := rec.Result().Header.Get("Location"); location != tt.wantLocation {
				t.Fatalf("Location = %q, want %q", location, tt.wantLocation)
			}
		})
	}
}

func TestPropertiesRejectsTraversalRename(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	form := url.Values{"csrf": {csrf}, "new_path": {"/docs/%2e%2e/escape.html"}}
	req := httptest.NewRequest(http.MethodPost, "/docs/page.html?properties", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusForbidden)
	}
	if _, err := os.Stat(filepath.Join(cfg.WEB_FILE_PATH, "docs/page.html")); err != nil {
		t.Fatalf("original file stat: %v", err)
	}
}

func TestSubpagesRejectsRelativeTraversalCreation(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	form := url.Values{"csrf": {csrf}, "path": {"../escape"}, "title": {"Escape"}}
	req := httptest.NewRequest(http.MethodPost, "/docs/page.html?subpages", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Result().StatusCode, http.StatusForbidden)
	}
	if _, err := os.Stat(filepath.Join(cfg.WEB_FILE_PATH, "escape.html")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("escaped subpage stat error = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.WEB_FILE_PATH, "docs/escape.html")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("docs subpage stat error = %v, want not exist", err)
	}
}

func TestPropertiesGetShowsCurrentMetadataFields(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	form := url.Values{
		"csrf":      {csrf},
		"new_path":  {"/docs/page.html"},
		"title":     {"Stored Title"},
		"tags":      {"one two"},
		"status":    {"draft"},
		"published": {"1"},
	}
	postReq := httptest.NewRequest(http.MethodPost, "/docs/page.html?properties", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(cookie)
	postRec := httptest.NewRecorder()
	handleRequest(cfg, postRec, postReq)
	if postRec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("properties post status = %d, want %d", postRec.Result().StatusCode, http.StatusSeeOther)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/docs/page.html?properties", nil)
	getReq.AddCookie(cookie)
	getRec := httptest.NewRecorder()
	handleRequest(cfg, getRec, getReq)
	body, err := io.ReadAll(getRec.Result().Body)
	if err != nil {
		t.Fatalf("read properties body: %v", err)
	}
	if getRec.Result().StatusCode != http.StatusOK ||
		!strings.Contains(string(body), "Current path: /docs/page.html") ||
		!strings.Contains(string(body), `value="Stored Title"`) ||
		!strings.Contains(string(body), `value="one two"`) ||
		!strings.Contains(string(body), `value="draft"`) {
		t.Fatalf("properties status/body = %d/%q, want persisted fields", getRec.Result().StatusCode, string(body))
	}
}

func TestSubpagesListsCanonicalPagesUnderCurrentPath(t *testing.T) {
	cfg, cookie, _ := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/index.html", "docs")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/a.html", "a")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/nested/index.html", "nested")
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "other.html", "other")

	req := httptest.NewRequest(http.MethodGet, "/docs/?subpages", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	handleRequest(cfg, rec, req)
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read subpages body: %v", err)
	}
	bodyText := string(body)
	if rec.Result().StatusCode != http.StatusOK ||
		!strings.Contains(bodyText, "/docs/a.html") ||
		!strings.Contains(bodyText, "/docs/nested/") ||
		strings.Contains(bodyText, "/other.html") ||
		strings.Contains(bodyText, "/docs/index.html") {
		t.Fatalf("subpages status/body = %d/%q, want canonical docs children only", rec.Result().StatusCode, bodyText)
	}
}

func TestConcurrentAuthenticatedEditsCreateConsecutiveJSONRevisions(t *testing.T) {
	cfg, cookie, csrf := loginTestUser(t)
	writeFixtureFile(t, cfg.WEB_FILE_PATH, "docs/page.html", "original")

	contents := []string{"first concurrent change", "second concurrent change"}
	start := make(chan struct{})
	statuses := make(chan int, len(contents))
	var wg sync.WaitGroup
	for _, content := range contents {
		content := content
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			form := url.Values{"content": {content}, "csrf": {csrf}}
			req := httptest.NewRequest(http.MethodPost, "/docs/page.html?edit", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()

			handleRequest(cfg, rec, req)
			statuses <- rec.Result().StatusCode
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)

	for status := range statuses {
		if status != http.StatusSeeOther {
			t.Fatalf("concurrent edit status = %d, want %d", status, http.StatusSeeOther)
		}
	}

	service := siteService{config: cfg, sessions: defaultSessions}
	records, err := service.loadRevisions("/docs/page.html")
	if err != nil {
		t.Fatalf("load revisions: %v", err)
	}
	if len(records) != len(contents) {
		t.Fatalf("revision records = %+v, want %d records", records, len(contents))
	}
	seenAfterContent := map[string]bool{}
	for i, record := range records {
		if record.Revision != i+1 {
			t.Fatalf("revision records = %+v, want consecutive revisions 1..%d", records, len(contents))
		}
		seenAfterContent[record.AfterContent] = true
	}
	for _, content := range contents {
		if !seenAfterContent[content] {
			t.Fatalf("revision after_content set = %v, missing %q", seenAfterContent, content)
		}
	}

	entries, err := os.ReadDir(service.revisionDir("/docs/page.html"))
	if err != nil {
		t.Fatalf("read revision dir: %v", err)
	}
	jsonFiles := 0
	names := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		jsonFiles++
		if names[entry.Name()] {
			t.Fatalf("duplicate revision filename %q", entry.Name())
		}
		names[entry.Name()] = true
	}
	if jsonFiles != len(contents) {
		t.Fatalf("json revision file count = %d (%v), want %d", jsonFiles, names, len(contents))
	}

	data, err := os.ReadFile(filepath.Join(cfg.WEB_FILE_PATH, "docs", "page.html"))
	if err != nil {
		t.Fatalf("read saved file: %v", err)
	}
	if !seenAfterContent[string(data)] {
		t.Fatalf("final file content = %q, want one of saved revision contents %v", string(data), seenAfterContent)
	}
}

func TestDBPostRevisionConfiguredSupportsPostgresWithoutFilePath(t *testing.T) {
	service := siteService{config: Config.Settings{DB_TYPE: "postgres"}}
	if !service.dbPostRevisionConfigured() {
		t.Fatal("postgres DB revisions should not require DB_FULL_FILE_PATH")
	}
	service = siteService{config: Config.Settings{DB_TYPE: "sqlite"}}
	if service.dbPostRevisionConfigured() {
		t.Fatal("sqlite DB revisions should require DB_FULL_FILE_PATH")
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

func loginPersistentTestUser(t *testing.T, password string) (Config.Settings, *http.Cookie, string, operatorSession) {
	t.Helper()
	defaultSessions = newSessionStore()
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD", "")
	t.Setenv("SITEBRUSH_ADMIN_PASSWORD_SHA256", "")

	root := t.TempDir()
	cfg := testConfig(t, root)
	service := siteService{config: cfg, sessions: defaultSessions}
	if _, err := service.createFirstAdmin("admin@example.test", password); err != nil {
		t.Fatalf("create first admin: %v", err)
	}

	form := url.Values{"email": {"admin@example.test"}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/?login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handleRequest(cfg, rec, req)

	if rec.Result().StatusCode != http.StatusSeeOther {
		t.Fatalf("persistent login status = %d, want %d", rec.Result().StatusCode, http.StatusSeeOther)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("persistent login did not set a session cookie")
	}
	cookie := cookies[0]
	sessionReq := httptest.NewRequest(http.MethodGet, "/?profile", nil)
	sessionReq.AddCookie(cookie)
	session, ok := defaultSessions.get(sessionReq)
	if !ok {
		t.Fatalf("persistent login cookie did not create a valid session")
	}
	return cfg, cookie, session.CSRFToken, session
}
