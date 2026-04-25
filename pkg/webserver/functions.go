package webserver

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	Config "sitebrush/pkg/config"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
)

const (
	sessionCookieName = "sitebrush_session"
	sessionDuration   = 12 * time.Hour
)

type siteService struct {
	config   Config.Settings
	sessions *sessionStore
}

type operatorSession struct {
	User      string
	CSRFToken string
	ExpiresAt time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]operatorSession
}

type revisionRecord struct {
	Revision      int       `json:"revision"`
	RequestURI    string    `json:"request_uri"`
	Path          string    `json:"path"`
	CreatedAt     time.Time `json:"created_at"`
	BeforeContent string    `json:"before_content"`
	AfterContent  string    `json:"after_content"`
	Checksum      string    `json:"checksum"`
}

type siteState struct {
	Frozen    bool      `json:"frozen"`
	UpdatedAt time.Time `json:"updated_at"`
}

type backupRecord struct {
	Path      string    `json:"path"`
	Checksum  string    `json:"checksum"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

var defaultSessions = newSessionStore()

func newSiteService(config Config.Settings) siteService {
	return siteService{config: config, sessions: defaultSessions}
}

// checkFileExist проверяет, существует ли файл в локальной директории.
func checkFileExist(fileName string) bool {
	_, err := os.Stat(fileName)
	return !os.IsNotExist(err)
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]operatorSession{}}
}

// checkUserLoggedIn проверяет, залогинен ли пользователь.
func checkUserLoggedIn(request *http.Request) bool {
	_, ok := defaultSessions.get(request)
	return ok
}

func (s *sessionStore) create(responseWriter http.ResponseWriter, request *http.Request, user string) (operatorSession, error) {
	token, err := randomToken(32)
	if err != nil {
		return operatorSession{}, err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return operatorSession{}, err
	}

	session := operatorSession{
		User:      user,
		CSRFToken: csrfToken,
		ExpiresAt: time.Now().Add(sessionDuration),
	}

	s.mu.Lock()
	s.sessions[hashToken(token)] = session
	s.mu.Unlock()

	http.SetCookie(responseWriter, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		Secure:   request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	return session, nil
}

func (s *sessionStore) get(request *http.Request) (operatorSession, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return operatorSession{}, false
	}

	key := hashToken(cookie.Value)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[key]
	if !ok {
		return operatorSession{}, false
	}
	if now.After(session.ExpiresAt) {
		delete(s.sessions, key)
		return operatorSession{}, false
	}
	return session, true
}

func (s *sessionStore) destroy(responseWriter http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, hashToken(cookie.Value))
		s.mu.Unlock()
	}

	http.SetCookie(responseWriter, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   request.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func randomToken(bytesCount int) (string, error) {
	buffer := make([]byte, bytesCount)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func adminPasswordConfigured() bool {
	return os.Getenv("SITEBRUSH_ADMIN_PASSWORD_SHA256") != "" ||
		os.Getenv("SITEBRUSH_ADMIN_PASSWORD") != ""
}

func validateAdminPassword(password string) bool {
	if hash := os.Getenv("SITEBRUSH_ADMIN_PASSWORD_SHA256"); hash != "" {
		sum := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare([]byte(strings.ToLower(hash)), []byte(hex.EncodeToString(sum[:]))) == 1
	}
	if configured := os.Getenv("SITEBRUSH_ADMIN_PASSWORD"); configured != "" {
		configuredSum := sha256.Sum256([]byte(configured))
		passwordSum := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(configuredSum[:], passwordSum[:]) == 1
	}
	return false
}

// loginFunction обрабатывает запросы на авторизацию пользователя.
func loginFunction(responseWriter http.ResponseWriter, request *http.Request) {
	service := newSiteService(Config.Settings{})
	service.login(responseWriter, request)
}

func (s siteService) login(responseWriter http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		status := http.StatusOK
		message := ""
		if !adminPasswordConfigured() {
			status = http.StatusServiceUnavailable
			message = "Admin password is not configured. Set SITEBRUSH_ADMIN_PASSWORD_SHA256 or SITEBRUSH_ADMIN_PASSWORD."
		}
		responseWriter.WriteHeader(status)
		renderHTML(responseWriter, "SiteBrush Login", loginFormTemplate, map[string]string{"Message": message})
	case http.MethodPost:
		if !adminPasswordConfigured() {
			http.Error(responseWriter, "Admin password is not configured", http.StatusServiceUnavailable)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid login request", http.StatusBadRequest)
			return
		}
		if !validateAdminPassword(request.FormValue("password")) {
			http.Error(responseWriter, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		if _, err := s.sessions.create(responseWriter, request, "admin"); err != nil {
			http.Error(responseWriter, "Could not create session", http.StatusInternalServerError)
			return
		}
		next := request.FormValue("next")
		if next == "" || strings.HasPrefix(next, "//") || !strings.HasPrefix(next, "/") {
			next = "/?profile"
		}
		http.Redirect(responseWriter, request, next, http.StatusSeeOther)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// editFunction обрабатывает запросы на редактирование файла.
func editFunction(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	service := newSiteService(Config.Settings{})
	service.edit(responseWriter, request, fileName)
}

func (s siteService) edit(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}

	switch request.Method {
	case http.MethodGet:
		body := ""
		if data, err := os.ReadFile(fileName); err == nil {
			body = string(data)
		} else if !errors.Is(err, os.ErrNotExist) {
			http.Error(responseWriter, "Could not load page", http.StatusInternalServerError)
			return
		}
		renderHTML(responseWriter, "Edit "+request.URL.Path, editFormTemplate, map[string]string{
			"Action": request.URL.Path + "?edit",
			"Body":   body,
			"CSRF":   session.CSRFToken,
		})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid edit request", http.StatusBadRequest)
			return
		}
		newContent := request.FormValue("content")
		if err := s.saveEditedFile(request, fileName, newContent); err != nil {
			http.Error(responseWriter, "Save failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(responseWriter, request, request.URL.Path+"?revisions", http.StatusSeeOther)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s siteService) saveEditedFile(request *http.Request, fileName, newContent string) error {
	oldContent := ""
	if data, err := os.ReadFile(fileName); err == nil {
		oldContent = string(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	revision, err := s.nextRevision(request.URL.Path)
	if err != nil {
		return err
	}
	record := revisionRecord{
		Revision:      revision,
		RequestURI:    request.URL.Path,
		Path:          request.URL.Path,
		CreatedAt:     time.Now().UTC(),
		BeforeContent: oldContent,
		AfterContent:  newContent,
		Checksum:      contentChecksum(newContent),
	}
	if err := s.writeRevision(record); err != nil {
		return err
	}
	return atomicWriteFile(fileName, []byte(newContent), 0o644)
}

func atomicWriteFile(fileName string, data []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(fileName), 0o755); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(filepath.Dir(fileName), "."+filepath.Base(fileName)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(mode); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, fileName); err != nil {
		return err
	}
	cleanup = false
	return syncDir(filepath.Dir(fileName))
}

func syncDir(dir string) error {
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

// deleteRevisionFunction обрабатывает запросы на удаление последней ревизии файла.
func deleteRevisionFunction(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	service := newSiteService(Config.Settings{})
	service.notImplementedMutation(responseWriter, request, "delete revision")
}

// showRevisionsFunction обрабатывает запросы на отображение всех ревизий файла.
func showRevisionsFunction(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	service := newSiteService(Config.Settings{})
	service.revisions(responseWriter, request, fileName)
}

func (s siteService) revisions(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}

	switch request.Method {
	case http.MethodGet:
		records, err := s.loadRevisions(request.URL.Path)
		if err != nil {
			http.Error(responseWriter, "Could not load revisions", http.StatusInternalServerError)
			return
		}
		renderHTML(responseWriter, "Revisions "+request.URL.Path, revisionsTemplate, map[string]any{
			"Records": records,
			"Action":  request.URL.Path + "?revisions",
			"CSRF":    session.CSRFToken,
		})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid restore request", http.StatusBadRequest)
			return
		}
		revision := request.FormValue("revision")
		if revision == "" {
			http.Error(responseWriter, "Missing revision", http.StatusBadRequest)
			return
		}
		record, err := s.findRevision(request.URL.Path, revision)
		if err != nil {
			http.Error(responseWriter, "Revision not found", http.StatusNotFound)
			return
		}
		if err := s.saveEditedFile(request, fileName, record.AfterContent); err != nil {
			http.Error(responseWriter, "Restore failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(responseWriter, request, request.URL.Path+"?revisions", http.StatusSeeOther)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// showSubpagesFunction обрабатывает запросы на отображение иерархического дерева файлов.
func showSubpagesFunction(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	service := newSiteService(Config.Settings{})
	service.subpages(responseWriter, request)
}

func (s siteService) subpages(responseWriter http.ResponseWriter, request *http.Request) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		pages, err := listStaticPages(s.config)
		if err != nil {
			http.Error(responseWriter, "Could not list subpages", http.StatusInternalServerError)
			return
		}
		renderHTML(responseWriter, "Subpages", subpagesTemplate, map[string]any{"Pages": pages})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		http.Error(responseWriter, "Subpage updates are not implemented yet", http.StatusNotImplemented)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// editPropertiesFunction обрабатывает запросы на редактирование свойств файла.
func editPropertiesFunction(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	service := newSiteService(Config.Settings{})
	service.properties(responseWriter, request)
}

func (s siteService) properties(responseWriter http.ResponseWriter, request *http.Request) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		renderHTML(responseWriter, "Properties", propertiesTemplate, map[string]string{"CSRF": session.CSRFToken})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		http.Error(responseWriter, "Property updates are not implemented yet", http.StatusNotImplemented)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// freezeSiteFunction обрабатывает запросы на заморозку сайта.
func freezeSiteFunction(responseWriter http.ResponseWriter, request *http.Request) {
	service := newSiteService(Config.Settings{})
	service.setFreeze(responseWriter, request, true)
}

// unfreezeSiteFunction обрабатывает запросы на разморозку сайта.
func unfreezeSiteFunction(responseWriter http.ResponseWriter, request *http.Request) {
	service := newSiteService(Config.Settings{})
	service.setFreeze(responseWriter, request, false)
}

func (s siteService) setFreeze(responseWriter http.ResponseWriter, request *http.Request, frozen bool) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		responseWriter.Header().Set("Allow", "POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validCSRF(request, session) {
		http.Error(responseWriter, "Forbidden", http.StatusForbidden)
		return
	}
	state := siteState{Frozen: frozen, UpdatedAt: time.Now().UTC()}
	if err := s.writeSiteState(state); err != nil {
		http.Error(responseWriter, "Could not update site state", http.StatusInternalServerError)
		return
	}
	status := "unfrozen"
	if frozen {
		status = "frozen"
	}
	fmt.Fprintf(responseWriter, "Site is %s", status)
}

// backupSiteFunction обрабатывает запросы на создание резервной копии сайта.
func backupSiteFunction(responseWriter http.ResponseWriter, request *http.Request) {
	service := newSiteService(Config.Settings{})
	service.backup(responseWriter, request)
}

func (s siteService) backup(responseWriter http.ResponseWriter, request *http.Request) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		responseWriter.Header().Set("Allow", "POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validCSRF(request, session) {
		http.Error(responseWriter, "Forbidden", http.StatusForbidden)
		return
	}
	record, err := s.createBackup()
	if err != nil {
		http.Error(responseWriter, "Backup failed", http.StatusInternalServerError)
		return
	}
	responseWriter.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(responseWriter).Encode(record)
}

// showProfileFunction обрабатывает запросы на отображение свойств учетной записи пользователя.
func showProfileFunction(responseWriter http.ResponseWriter, request *http.Request) {
	service := newSiteService(Config.Settings{})
	service.profile(responseWriter, request)
}

func (s siteService) profile(responseWriter http.ResponseWriter, request *http.Request) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		renderHTML(responseWriter, "Profile", profileTemplate, map[string]string{
			"User":    session.User,
			"Expires": session.ExpiresAt.Format(time.RFC3339),
			"Site":    s.config.WEB_FILE_PATH,
			"CSRF":    session.CSRFToken,
		})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		http.Error(responseWriter, "Profile updates are not implemented yet", http.StatusNotImplemented)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// logoutFunction обрабатывает запросы на выход из учетной записи.
func logoutFunction(responseWriter http.ResponseWriter, request *http.Request) {
	service := newSiteService(Config.Settings{})
	service.logout(responseWriter, request)
}

func (s siteService) logout(responseWriter http.ResponseWriter, request *http.Request) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		renderHTML(responseWriter, "Logout", logoutTemplate, map[string]string{"CSRF": session.CSRFToken})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		s.sessions.destroy(responseWriter, request)
		http.Redirect(responseWriter, request, "/?login", http.StatusSeeOther)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s siteService) notImplementedMutation(responseWriter http.ResponseWriter, request *http.Request, name string) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		responseWriter.Header().Set("Allow", "POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validCSRF(request, session) {
		http.Error(responseWriter, "Forbidden", http.StatusForbidden)
		return
	}
	http.Error(responseWriter, name+" is not implemented yet", http.StatusNotImplemented)
}

func (s siteService) notImplementedPublic(responseWriter http.ResponseWriter, request *http.Request, name string) {
	switch request.Method {
	case http.MethodGet, http.MethodPost:
		http.Error(responseWriter, name+" is not implemented yet", http.StatusNotImplemented)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s siteService) requireAuth(responseWriter http.ResponseWriter, request *http.Request) (operatorSession, bool) {
	session, ok := s.sessions.get(request)
	if ok {
		return session, true
	}
	responseWriter.Header().Set("Content-Type", "text/plain; charset=utf-8")
	responseWriter.Header().Set("WWW-Authenticate", "SiteBrush")
	responseWriter.WriteHeader(http.StatusUnauthorized)
	_, _ = fmt.Fprint(responseWriter, "Authentication required. Visit /?login.")
	return operatorSession{}, false
}

func (s siteService) validCSRF(request *http.Request, session operatorSession) bool {
	token := request.Header.Get("X-CSRF-Token")
	if token == "" {
		if err := request.ParseForm(); err != nil {
			return false
		}
		token = request.FormValue("csrf")
	}
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(session.CSRFToken)) == 1
}

func requestedFilePath(config Config.Settings, requestPath string) string {
	fileName, err := safeRequestedFilePath(config, requestPath)
	if err != nil {
		return ""
	}
	return fileName
}

func safeRequestedFilePath(config Config.Settings, requestPath string) (string, error) {
	return safePathUnderRoot(config.WEB_FILE_PATH, requestPath, config.WEB_INDEX_FILE, true)
}

func safePathUnderRoot(root, requestPath, indexFile string, appendIndex bool) (string, error) {
	if requestPath == "" {
		requestPath = "/"
	}

	unescapedPath, err := url.PathUnescape(requestPath)
	if err != nil {
		return "", err
	}
	if strings.Contains(unescapedPath, `\`) {
		return "", errors.New("unsafe path")
	}
	if strings.HasPrefix(unescapedPath, "//") {
		return "", errors.New("unsafe path")
	}

	segments := strings.Split(unescapedPath, "/")
	for _, segment := range segments {
		if segment == ".." || strings.Contains(segment, ":") {
			return "", errors.New("unsafe path")
		}
	}

	isDirectory := strings.HasSuffix(unescapedPath, "/")
	cleanedPath := pathpkg.Clean("/" + strings.TrimPrefix(unescapedPath, "/"))
	relativePath := strings.TrimPrefix(cleanedPath, "/")
	if relativePath == "." {
		relativePath = ""
	}
	if appendIndex && (relativePath == "" || isDirectory) {
		relativePath = pathpkg.Join(relativePath, indexFile)
	}

	rootPath, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	targetPath, err := filepath.Abs(filepath.Join(rootPath, filepath.FromSlash(relativePath)))
	if err != nil {
		return "", err
	}
	if !pathIsInsideRoot(rootPath, targetPath) {
		return "", errors.New("unsafe path")
	}

	evaluatedRoot, err := filepath.EvalSymlinks(rootPath)
	if err == nil {
		if evaluatedTarget, err := filepath.EvalSymlinks(targetPath); err == nil && !pathIsInsideRoot(evaluatedRoot, evaluatedTarget) {
			return "", errors.New("unsafe path")
		}
	}

	return targetPath, nil
}

func pathIsInsideRoot(rootPath, targetPath string) bool {
	relativePath, err := filepath.Rel(rootPath, targetPath)
	if err != nil {
		return false
	}
	return relativePath == "." || (!filepath.IsAbs(relativePath) && relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator)))
}

type domainPaths struct {
	PublicRoot  string
	ArchiveRoot string
	CacheRoot   string
	MediaRoot   string
}

func canonicalHostFromRequest(request *http.Request) (string, error) {
	if request == nil {
		return "", errors.New("missing request")
	}
	return canonicalHost(request.Host)
}

func canonicalHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("empty host")
	}
	if len(host) > 255 {
		return "", errors.New("host too long")
	}
	if strings.TrimSpace(host) != host {
		return "", errors.New("invalid host whitespace")
	}
	if strings.ContainsAny(host, `/\`) {
		return "", errors.New("path-like host")
	}
	if strings.IndexFunc(host, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return "", errors.New("invalid host character")
	}

	hostOnly := host
	if strings.HasPrefix(hostOnly, "[") {
		end := strings.Index(hostOnly, "]")
		if end <= 1 {
			return "", errors.New("invalid host")
		}
		literal := hostOnly[1:end]
		if net.ParseIP(literal) == nil {
			return "", errors.New("invalid bracketed host")
		}
		remainder := hostOnly[end+1:]
		if remainder != "" {
			if !strings.HasPrefix(remainder, ":") || !allDigits(remainder[1:]) {
				return "", errors.New("invalid host port")
			}
		}
		hostOnly = literal
	} else if splitHost, port, err := net.SplitHostPort(hostOnly); err == nil {
		if !allDigits(port) {
			return "", errors.New("invalid host port")
		}
		hostOnly = splitHost
	} else if colon := strings.LastIndex(hostOnly, ":"); colon >= 0 {
		port := hostOnly[colon+1:]
		candidateHost := hostOnly[:colon]
		if strings.Count(hostOnly, ":") == 1 && candidateHost != "" && allDigits(port) {
			hostOnly = candidateHost
		} else if net.ParseIP(hostOnly) == nil {
			return "", errors.New("invalid host")
		}
	}

	hostOnly = strings.TrimSuffix(strings.ToLower(hostOnly), ".")
	if hostOnly == "" {
		return "", errors.New("empty host")
	}
	if len(hostOnly) > 253 {
		return "", errors.New("host too long")
	}
	if ip := net.ParseIP(hostOnly); ip != nil {
		return hostOnly, nil
	}
	if hostOnly == "localhost" {
		return hostOnly, nil
	}
	if strings.Contains(hostOnly, "_") {
		return "", errors.New("invalid host character")
	}

	labels := strings.Split(hostOnly, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", errors.New("invalid host label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("invalid host label")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", errors.New("invalid host character")
		}
	}
	return hostOnly, nil
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func (s siteService) domainPaths(host string) (domainPaths, error) {
	canonical, err := canonicalHost(host)
	if err != nil {
		return domainPaths{}, err
	}
	publicRoot, err := safeJoinUnderRoot(s.config.WEB_FILE_PATH, "domains", canonical, "public")
	if err != nil {
		return domainPaths{}, err
	}
	archiveRoot, err := safeJoinUnderRoot(s.archiveRoot(), "domains", canonical)
	if err != nil {
		return domainPaths{}, err
	}
	cacheRoot, err := safeJoinUnderRoot(archiveRoot, "cache", "cleanhtml")
	if err != nil {
		return domainPaths{}, err
	}
	mediaRoot, err := safeJoinUnderRoot(archiveRoot, "media")
	if err != nil {
		return domainPaths{}, err
	}
	return domainPaths{
		PublicRoot:  publicRoot,
		ArchiveRoot: archiveRoot,
		CacheRoot:   cacheRoot,
		MediaRoot:   mediaRoot,
	}, nil
}

func safeJoinUnderRoot(root string, elems ...string) (string, error) {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	parts := append([]string{rootPath}, elems...)
	targetPath, err := filepath.Abs(filepath.Join(parts...))
	if err != nil {
		return "", err
	}
	if !pathIsInsideRoot(rootPath, targetPath) {
		return "", errors.New("unsafe path")
	}
	return targetPath, nil
}

func handleRequest(config Config.Settings, responseWriter http.ResponseWriter, request *http.Request) {
	service := siteService{config: config, sessions: defaultSessions}
	service.handle(responseWriter, request)
}

func (s siteService) handle(responseWriter http.ResponseWriter, request *http.Request) {
	if s.handleLegacyStatic(responseWriter, request) {
		return
	}

	fileName, err := safeRequestedFilePath(s.config, request.URL.Path)
	if err != nil {
		http.Error(responseWriter, "Forbidden", http.StatusForbidden)
		return
	}
	action, err := parseAction(request.URL.RawQuery)
	if err != nil {
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
		return
	}

	log.Println(request.URL)

	switch action {
	case "":
		if !checkFileExist(fileName) {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return
		}
		http.ServeFile(responseWriter, request, fileName)
	case "login":
		s.login(responseWriter, request)
	case "edit":
		s.edit(responseWriter, request, fileName)
	case "delete":
		s.notImplementedMutation(responseWriter, request, "delete revision")
	case "revisions":
		s.revisions(responseWriter, request, fileName)
	case "subpages":
		s.subpages(responseWriter, request)
	case "properties":
		s.properties(responseWriter, request)
	case "freeze":
		s.setFreeze(responseWriter, request, true)
	case "unfreeze":
		s.setFreeze(responseWriter, request, false)
	case "backup":
		s.backup(responseWriter, request)
	case "profile":
		s.profile(responseWriter, request)
	case "logout":
		s.logout(responseWriter, request)
	case "join", "verify", "recover", "captcha":
		s.notImplementedPublic(responseWriter, request, action)
	case "upload", "grab", "domains", "undelete":
		s.notImplementedMutation(responseWriter, request, action)
	default:
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
	}
}

func (s siteService) handleLegacyStatic(responseWriter http.ResponseWriter, request *http.Request) bool {
	if request.URL.RawQuery != "" {
		return false
	}
	switch {
	case request.URL.Path == "/b" || strings.HasPrefix(request.URL.Path, "/b/"):
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
		return true
	case request.URL.Path == "/p" || strings.HasPrefix(request.URL.Path, "/p/"),
		request.URL.Path == "/d" || strings.HasPrefix(request.URL.Path, "/d/"):
		fileName, err := safeRequestedFilePath(s.config, request.URL.Path)
		if err != nil {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return true
		}
		if !checkFileExist(fileName) {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return true
		}
		http.ServeFile(responseWriter, request, fileName)
		return true
	case request.URL.Path == "/f" || strings.HasPrefix(request.URL.Path, "/f/"):
		host, err := canonicalHostFromRequest(request)
		if err != nil {
			http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
			return true
		}
		roots, err := s.domainPaths(host)
		if err != nil {
			http.Error(responseWriter, "Bad Request", http.StatusBadRequest)
			return true
		}
		mediaPath := strings.TrimPrefix(request.URL.Path, "/f")
		if mediaPath == "" || mediaPath == "/" {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return true
		}
		fileName, err := safePathUnderRoot(roots.MediaRoot, mediaPath, "", false)
		if err != nil {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return true
		}
		info, err := os.Stat(fileName)
		if err != nil || info.IsDir() {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return true
		}
		http.ServeFile(responseWriter, request, fileName)
		return true
	default:
		return false
	}
}

func parseAction(rawQuery string) (string, error) {
	if rawQuery == "" {
		return "", nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) != 1 {
		return "", errors.New("invalid query")
	}
	for key, value := range values {
		if len(value) > 1 || (len(value) == 1 && value[0] != "") {
			return "", errors.New("invalid query")
		}
		switch key {
		case "login", "edit", "delete", "revisions", "subpages", "properties", "freeze", "unfreeze", "backup", "profile", "logout",
			"join", "verify", "recover", "upload", "grab", "domains", "undelete", "captcha":
			return key, nil
		default:
			return "", errors.New("unknown action")
		}
	}
	return "", errors.New("invalid query")
}

func (s siteService) archiveRoot() string {
	dbPath := s.config.DB_FILE_PATH
	if dbPath == "" && s.config.DB_FULL_FILE_PATH != "" {
		dbPath = filepath.Dir(s.config.DB_FULL_FILE_PATH)
	}
	if dbPath == "" {
		dbPath = "."
	}
	return filepath.Join(dbPath, "sitebrush-archives", siteHash(s.config.WEB_FILE_PATH))
}

func siteHash(sitePath string) string {
	sum := sha256.Sum256([]byte(sitePath))
	return hex.EncodeToString(sum[:])[:16]
}

func contentChecksum(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func (s siteService) revisionDir(requestURI string) string {
	safeName := strings.Trim(strings.ReplaceAll(pathpkg.Clean("/"+strings.TrimPrefix(requestURI, "/")), "/", "_"), "_")
	if safeName == "" {
		safeName = "index"
	}
	return filepath.Join(s.archiveRoot(), "revisions", safeName)
}

func (s siteService) nextRevision(requestURI string) (int, error) {
	records, err := s.loadRevisions(requestURI)
	if err != nil {
		return 0, err
	}
	return len(records) + 1, nil
}

func (s siteService) writeRevision(record revisionRecord) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	dir := s.revisionDir(record.RequestURI)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	name := fmt.Sprintf("%06d-%s.json", record.Revision, record.CreatedAt.Format("20060102T150405Z"))
	return atomicWriteFile(filepath.Join(dir, name), data, 0o600)
}

func (s siteService) loadRevisions(requestURI string) ([]revisionRecord, error) {
	dir := s.revisionDir(requestURI)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	records := make([]revisionRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var record revisionRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Revision < records[j].Revision
	})
	return records, nil
}

func (s siteService) findRevision(requestURI, revision string) (revisionRecord, error) {
	records, err := s.loadRevisions(requestURI)
	if err != nil {
		return revisionRecord{}, err
	}
	for _, record := range records {
		if fmt.Sprint(record.Revision) == revision {
			return record, nil
		}
	}
	return revisionRecord{}, errors.New("revision not found")
}

func (s siteService) statePath() string {
	return filepath.Join(s.archiveRoot(), "site-state.json")
}

func (s siteService) writeSiteState(state siteState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.statePath(), data, 0o600)
}

func (s siteService) createBackup() (backupRecord, error) {
	rootPath, err := filepath.Abs(s.config.WEB_FILE_PATH)
	if err != nil {
		return backupRecord{}, err
	}
	backupDir := filepath.Join(s.archiveRoot(), "backups")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return backupRecord{}, err
	}
	absoluteBackupDir, err := filepath.Abs(backupDir)
	if err != nil {
		return backupRecord{}, err
	}
	if pathIsInsideRoot(rootPath, absoluteBackupDir) {
		return backupRecord{}, errors.New("backup destination cannot be inside web root")
	}

	tmpFile, err := os.CreateTemp(backupDir, "sitebrush-backup-*.zip.tmp")
	if err != nil {
		return backupRecord{}, err
	}
	tmpName := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	zipWriter := zip.NewWriter(tmpFile)
	if err := filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if !pathIsInsideRoot(rootPath, absolutePath) {
			return errors.New("unsafe backup path")
		}
		relativePath, err := filepath.Rel(rootPath, absolutePath)
		if err != nil {
			return err
		}
		archivePath := filepath.ToSlash(relativePath)
		writer, err := zipWriter.Create(archivePath)
		if err != nil {
			return err
		}
		source, err := os.Open(absolutePath)
		if err != nil {
			return err
		}
		defer source.Close()
		_, err = io.Copy(writer, source)
		return err
	}); err != nil {
		_ = zipWriter.Close()
		_ = tmpFile.Close()
		return backupRecord{}, err
	}
	if err := zipWriter.Close(); err != nil {
		_ = tmpFile.Close()
		return backupRecord{}, err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return backupRecord{}, err
	}
	if err := tmpFile.Close(); err != nil {
		return backupRecord{}, err
	}

	finalPath := filepath.Join(backupDir, "sitebrush-backup-"+time.Now().UTC().Format("20060102T150405Z")+".zip")
	if err := os.Rename(tmpName, finalPath); err != nil {
		return backupRecord{}, err
	}
	cleanup = false

	checksum, size, err := fileChecksum(finalPath)
	if err != nil {
		return backupRecord{}, err
	}
	record := backupRecord{Path: finalPath, Checksum: checksum, Size: size, CreatedAt: time.Now().UTC()}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return backupRecord{}, err
	}
	if err := atomicWriteFile(finalPath+".json", data, 0o600); err != nil {
		return backupRecord{}, err
	}
	if err := s.recordBackup(record, "complete", ""); err != nil {
		return backupRecord{}, err
	}
	return record, nil
}

func (s siteService) recordBackup(record backupRecord, status, errorMessage string) error {
	if s.config.DB_TYPE != "sqlite" || s.config.DB_FULL_FILE_PATH == "" {
		return nil
	}
	db, err := sql.Open("sqlite", s.config.DB_FULL_FILE_PATH)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS Backup (
		Id INTEGER PRIMARY KEY,
		Path TEXT,
		Checksum TEXT,
		Size INTEGER,
		CreatedAt INTEGER,
		Status TEXT,
		Error TEXT
	)`); err != nil {
		return err
	}
	_, err = db.Exec(
		"INSERT INTO Backup (Path, Checksum, Size, CreatedAt, Status, Error) VALUES (?, ?, ?, ?, ?, ?)",
		record.Path,
		record.Checksum,
		record.Size,
		record.CreatedAt.UnixMilli(),
		status,
		errorMessage,
	)
	return err
}

func fileChecksum(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func listStaticPages(config Config.Settings) ([]string, error) {
	rootPath, err := filepath.Abs(config.WEB_FILE_PATH)
	if err != nil {
		return nil, err
	}
	pages := []string{}
	err = filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if filepath.Ext(entry.Name()) != ".html" {
			return nil
		}
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if !pathIsInsideRoot(rootPath, absolutePath) {
			return errors.New("unsafe subpage path")
		}
		relativePath, err := filepath.Rel(rootPath, absolutePath)
		if err != nil {
			return err
		}
		pages = append(pages, "/"+filepath.ToSlash(relativePath))
		return nil
	})
	sort.Strings(pages)
	return pages, err
}

func renderHTML(responseWriter http.ResponseWriter, title, body string, data any) {
	responseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
	page := `<!doctype html><html><head><meta charset="utf-8"><title>{{.Title}}</title></head><body><h1>{{.Title}}</h1>` + body + `</body></html>`
	tmpl := template.Must(template.New("page").Parse(page))
	_ = tmpl.Execute(responseWriter, map[string]any{"Title": title, "Data": data})
}

const loginFormTemplate = `
{{with .Data.Message}}<p>{{.}}</p>{{end}}
<form method="post" action="/?login">
  <label>Password <input type="password" name="password" autocomplete="current-password"></label>
  <button type="submit">Log in</button>
</form>`

const editFormTemplate = `
<form method="post" action="{{.Data.Action}}">
  <input type="hidden" name="csrf" value="{{.Data.CSRF}}">
  <textarea name="content" rows="30" cols="120">{{.Data.Body}}</textarea>
  <p><button type="submit">Save</button></p>
</form>`

const revisionsTemplate = `
{{if .Data.Records}}
<ol>{{range .Data.Records}}<li>Revision {{.Revision}} at {{.CreatedAt}} checksum {{.Checksum}}
<form method="post" action="{{$.Data.Action}}">
  <input type="hidden" name="csrf" value="{{$.Data.CSRF}}">
  <input type="hidden" name="revision" value="{{.Revision}}">
  <button type="submit">Restore</button>
</form></li>{{end}}</ol>
{{else}}<p>No revisions.</p>{{end}}`

const subpagesTemplate = `
{{if .Data.Pages}}<ul>{{range .Data.Pages}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>No pages found.</p>{{end}}
<p>Navigation metadata updates are deferred for the MVP.</p>`

const propertiesTemplate = `
<p>Property editing is deferred for the MVP text/code editing slice.</p>
<form method="post"><input type="hidden" name="csrf" value="{{.Data.CSRF}}"><button type="submit">Save properties</button></form>`

const profileTemplate = `
<p>User: {{.Data.User}}</p>
<p>Session expires: {{.Data.Expires}}</p>
<p>Site root: {{.Data.Site}}</p>`

const logoutTemplate = `
<form method="post" action="/?logout"><input type="hidden" name="csrf" value="{{.Data.CSRF}}"><button type="submit">Log out</button></form>`
