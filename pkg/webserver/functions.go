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
	Data "sitebrush/pkg/data"
	Database "sitebrush/pkg/database"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
)

const (
	sessionCookieName = "sitebrush_session"
	sessionDuration   = 12 * time.Hour
	defaultDBDomain   = "default"
	healthzPath       = "/sitebrush-healthz"
)

var errUnsafePath = errors.New("unsafe path")

type siteService struct {
	config   Config.Settings
	sessions *sessionStore
}

type operatorSession struct {
	User       string
	Email      string
	UserID     int64
	AuthSource string
	CSRFToken  string
	ExpiresAt  time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]operatorSession
}

type revisionRecord struct {
	Revision          int       `json:"revision"`
	RequestURI        string    `json:"request_uri"`
	Path              string    `json:"path"`
	CreatedAt         time.Time `json:"created_at"`
	BeforeContent     string    `json:"before_content"`
	AfterContent      string    `json:"after_content"`
	Checksum          string    `json:"checksum"`
	DBRevisionWarning string    `json:"db_revision_warning,omitempty"`
}

type dbRevisionMetadata struct {
	Revision   int
	RequestURI string
	Domain     string
	Type       string
	Title      string
	Status     string
	Published  bool
	CreatedAt  time.Time
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

type healthResponse struct {
	Status string `json:"status"`
}

type restoreRollbackEntry struct {
	Path        string
	Root        string
	Exists      bool
	Content     []byte
	Mode        fs.FileMode
	CreatedDirs []string
}

type restoreTarget struct {
	ArchiveName string
	Path        string
	Root        string
	File        *zip.File
}

type pageMetadata struct {
	Path      string    `json:"path"`
	Title     string    `json:"title"`
	Tags      string    `json:"tags"`
	Status    string    `json:"status"`
	Published bool      `json:"published"`
	UpdatedAt time.Time `json:"updated_at"`
}

var defaultSessions = newSessionStore()
var revisionWriteLocks = newKeyedMutex()
var redirectFileLock sync.Mutex

type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: map[string]*keyedLock{}}
}

func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	lock := k.locks[key]
	if lock == nil {
		lock = &keyedLock{}
		k.locks[key] = lock
	}
	lock.refs++
	k.mu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()

		k.mu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

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
	return s.createForUser(responseWriter, request, user, "", 0, "env")
}

func (s *sessionStore) createForUser(responseWriter http.ResponseWriter, request *http.Request, user, email string, userID int64, authSource string) (operatorSession, error) {
	token, err := randomToken(32)
	if err != nil {
		return operatorSession{}, err
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		return operatorSession{}, err
	}

	session := operatorSession{
		User:       user,
		Email:      email,
		UserID:     userID,
		AuthSource: authSource,
		CSRFToken:  csrfToken,
		ExpiresAt:  time.Now().Add(sessionDuration),
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

func bootstrapTokenConfigured() bool {
	return os.Getenv("SITEBRUSH_BOOTSTRAP_TOKEN") != ""
}

func validateBootstrapToken(token string) bool {
	configured := os.Getenv("SITEBRUSH_BOOTSTRAP_TOKEN")
	if configured == "" || token == "" {
		return false
	}
	configuredSum := sha256.Sum256([]byte(configured))
	tokenSum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(configuredSum[:], tokenSum[:]) == 1
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
		hasPersistentUsers, err := s.hasPersistentUsers()
		if err != nil {
			status = http.StatusInternalServerError
			message = "Could not load user store."
		} else if !hasPersistentUsers && !adminPasswordConfigured() && !bootstrapTokenConfigured() {
			status = http.StatusServiceUnavailable
			message = "Admin access is not configured. Set SITEBRUSH_BOOTSTRAP_TOKEN for first-admin setup or SITEBRUSH_ADMIN_PASSWORD_SHA256/SITEBRUSH_ADMIN_PASSWORD for env-admin login."
		}
		responseWriter.WriteHeader(status)
		renderHTML(responseWriter, "SiteBrush Login", loginFormTemplate, map[string]string{"Message": message})
	case http.MethodPost:
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid login request", http.StatusBadRequest)
			return
		}
		password := request.FormValue("password")
		email := normalizeEmail(request.FormValue("email"))
		hasPersistentUsers, err := s.hasPersistentUsers()
		if err != nil {
			http.Error(responseWriter, "Could not load user store", http.StatusInternalServerError)
			return
		}
		if hasPersistentUsers && email != "" {
			user, ok, err := s.authenticatePersistentUser(email, password)
			if err != nil {
				http.Error(responseWriter, "Could not authenticate", http.StatusInternalServerError)
				return
			}
			if ok {
				if _, err := s.sessions.createForUser(responseWriter, request, displayUserName(user), user.Email, user.Id, "persistent"); err != nil {
					http.Error(responseWriter, "Could not create session", http.StatusInternalServerError)
					return
				}
				redirectAfterLogin(responseWriter, request)
				return
			}
			http.Error(responseWriter, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		if !adminPasswordConfigured() {
			http.Error(responseWriter, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		if !validateAdminPassword(password) {
			http.Error(responseWriter, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		if _, err := s.sessions.create(responseWriter, request, "admin"); err != nil {
			http.Error(responseWriter, "Could not create session", http.StatusInternalServerError)
			return
		}
		redirectAfterLogin(responseWriter, request)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func redirectAfterLogin(responseWriter http.ResponseWriter, request *http.Request) {
	next := request.FormValue("next")
	if next == "" || strings.HasPrefix(next, "//") || !strings.HasPrefix(next, "/") {
		next = "/?profile"
	}
	http.Redirect(responseWriter, request, next, http.StatusSeeOther)
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
		if err := s.saveEditedFile(request, session, fileName, newContent); err != nil {
			http.Error(responseWriter, "Save failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(responseWriter, request, request.URL.Path+"?revisions", http.StatusSeeOther)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s siteService) saveEditedFile(request *http.Request, session operatorSession, fileName, newContent string) error {
	requestURI, err := s.canonicalRequestURIForFile(fileName)
	if err != nil {
		return err
	}

	unlock := revisionWriteLocks.lock(s.revisionLockKey(requestURI))
	defer unlock()

	oldContent := ""
	if data, err := os.ReadFile(fileName); err == nil {
		oldContent = string(data)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	revision, err := s.nextRevision(requestURI)
	if err != nil {
		return err
	}
	record := revisionRecord{
		Revision:      revision,
		RequestURI:    requestURI,
		Path:          requestURI,
		CreatedAt:     time.Now().UTC(),
		BeforeContent: oldContent,
		AfterContent:  newContent,
		Checksum:      contentChecksum(newContent),
	}
	revisionPath, err := s.writeRevision(record)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(fileName, []byte(newContent), 0o644); err != nil {
		return err
	}
	if err := s.saveDBPostRevision(request, session, record); err != nil {
		warning := fmt.Sprintf("database post revision was not saved: %v", err)
		log.Printf("SiteBrush DB revision warning for %s: %s", record.RequestURI, warning)
		record.DBRevisionWarning = warning
		if markerErr := s.writeRevisionAtPath(record, revisionPath); markerErr != nil {
			log.Printf("SiteBrush DB revision warning marker failed for %s: %v", record.RequestURI, markerErr)
		}
	}
	return nil
}

func (s siteService) saveDBPostRevision(request *http.Request, session operatorSession, record revisionRecord) error {
	if !s.dbPostRevisionConfigured() {
		return nil
	}
	domain, trusted := trustedDBRevisionDomain(request)
	if !trusted {
		log.Printf("SiteBrush DB revision using default domain for untrusted host %q", request.Host)
	}
	post := Data.Post{
		OwnerId:    int(session.UserID),
		EditorId:   int(session.UserID),
		RequestUri: record.RequestURI,
		Type:       "Wiki",
		Date:       record.CreatedAt.UnixMilli(),
		Title:      titleFromRequestURI(record.RequestURI),
		Body:       record.AfterContent,
		Tags:       "",
		Domain:     domain,
		Status:     "active",
		Published:  true,
	}
	_, err := Database.SavePostRevisionFromConfig(s.config, post)
	return err
}

func (s siteService) dbPostRevisionConfigured() bool {
	switch s.config.DB_TYPE {
	case "postgres":
		return true
	case "sqlite", "genji":
		return s.config.DB_FULL_FILE_PATH != ""
	default:
		return false
	}
}

func titleFromRequestURI(requestURI string) string {
	cleaned := pathpkg.Clean("/" + strings.TrimPrefix(requestURI, "/"))
	if cleaned == "/" || cleaned == "." {
		return "Home"
	}
	base := pathpkg.Base(cleaned)
	base = strings.TrimSuffix(base, pathpkg.Ext(base))
	base = strings.ReplaceAll(base, "-", " ")
	base = strings.ReplaceAll(base, "_", " ")
	base = strings.TrimSpace(base)
	if base == "" || base == "." {
		return cleaned
	}
	return base
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
		requestURI, err := s.canonicalRequestURIForFile(fileName)
		if err != nil {
			http.Error(responseWriter, "Could not load revisions", http.StatusInternalServerError)
			return
		}
		records, err := s.loadRevisions(requestURI)
		if err != nil {
			http.Error(responseWriter, "Could not load revisions", http.StatusInternalServerError)
			return
		}
		dbRecords, err := s.loadDBRevisionMetadata(request, requestURI)
		if err != nil {
			http.Error(responseWriter, "Could not load database revisions", http.StatusInternalServerError)
			return
		}
		renderHTML(responseWriter, "Revisions "+request.URL.Path, revisionsTemplate, map[string]any{
			"Records":   records,
			"DBRecords": dbRecords,
			"Action":    request.URL.Path + "?revisions",
			"CSRF":      session.CSRFToken,
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
		requestURI, err := s.canonicalRequestURIForFile(fileName)
		if err != nil {
			http.Error(responseWriter, "Revision not found", http.StatusNotFound)
			return
		}
		record, err := s.findRevision(requestURI, revision)
		if err != nil {
			http.Error(responseWriter, "Revision not found", http.StatusNotFound)
			return
		}
		if err := s.saveEditedFile(request, session, fileName, record.AfterContent); err != nil {
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
	service.subpages(responseWriter, request, fileName)
}

func (s siteService) subpages(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		requestURI, err := s.canonicalRequestURIForFile(fileName)
		if err != nil {
			http.Error(responseWriter, "Could not list subpages", http.StatusInternalServerError)
			return
		}
		pages, err := s.listStaticPagesUnder(requestURI)
		if err != nil {
			http.Error(responseWriter, "Could not list subpages", http.StatusInternalServerError)
			return
		}
		renderHTML(responseWriter, "Subpages", subpagesTemplate, map[string]any{
			"CurrentPath": requestURI,
			"Pages":       pages,
			"Action":      request.URL.Path + "?subpages",
			"CSRF":        session.CSRFToken,
		})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid subpage request", http.StatusBadRequest)
			return
		}
		if err := s.createSubpage(fileName, request.FormValue("path"), request.FormValue("title")); err != nil {
			switch {
			case errors.Is(err, errUnsafePath):
				http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			case errors.Is(err, os.ErrExist):
				http.Error(responseWriter, "Subpage already exists", http.StatusConflict)
			default:
				http.Error(responseWriter, "Could not create subpage", http.StatusInternalServerError)
			}
			return
		}
		http.Redirect(responseWriter, request, request.URL.Path+"?subpages", http.StatusSeeOther)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

// editPropertiesFunction обрабатывает запросы на редактирование свойств файла.
func editPropertiesFunction(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	service := newSiteService(Config.Settings{})
	service.properties(responseWriter, request, fileName)
}

func (s siteService) properties(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		requestURI, err := s.canonicalRequestURIForFile(fileName)
		if err != nil {
			http.Error(responseWriter, "Could not load properties", http.StatusInternalServerError)
			return
		}
		metadata, err := s.loadPageMetadata(request, requestURI)
		if err != nil {
			http.Error(responseWriter, "Could not load properties", http.StatusInternalServerError)
			return
		}
		renderHTML(responseWriter, "Properties", propertiesTemplate, map[string]any{
			"Action":    request.URL.Path + "?properties",
			"CSRF":      session.CSRFToken,
			"Path":      requestURI,
			"NewPath":   requestURI,
			"Title":     metadata.Title,
			"Tags":      metadata.Tags,
			"Status":    metadata.Status,
			"Published": metadata.Published,
		})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid properties request", http.StatusBadRequest)
			return
		}
		newURI, err := s.updateProperties(request, fileName)
		if err != nil {
			switch {
			case errors.Is(err, errUnsafePath):
				http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			case errors.Is(err, os.ErrExist):
				http.Error(responseWriter, "Target path already exists", http.StatusConflict)
			default:
				http.Error(responseWriter, "Property update failed", http.StatusInternalServerError)
			}
			return
		}
		http.Redirect(responseWriter, request, newURI+"?properties", http.StatusSeeOther)
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
	if err := s.publishSnapshot(); err != nil {
		http.Error(responseWriter, "Could not publish site snapshot", http.StatusInternalServerError)
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
	if request.FormValue("restore") != "" {
		record, err := s.restoreBackup(request.FormValue("path"))
		if err != nil {
			switch {
			case errors.Is(err, errUnsafePath):
				http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			case errors.Is(err, os.ErrNotExist):
				http.Error(responseWriter, "Backup not found", http.StatusNotFound)
			default:
				http.Error(responseWriter, "Restore failed", http.StatusBadRequest)
			}
			return
		}
		responseWriter.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(responseWriter).Encode(record)
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
			"Email":   session.Email,
			"Source":  session.AuthSource,
			"Expires": session.ExpiresAt.Format(time.RFC3339),
			"Site":    s.config.WEB_FILE_PATH,
			"CSRF":    session.CSRFToken,
		})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		if session.AuthSource != "persistent" || session.UserID == 0 {
			http.Error(responseWriter, "Profile updates for environment admin sessions are not implemented yet", http.StatusNotImplemented)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid profile request", http.StatusBadRequest)
			return
		}
		currentPassword := request.FormValue("current_password")
		newPassword := request.FormValue("new_password")
		if currentPassword == "" || newPassword == "" {
			http.Error(responseWriter, "Missing password fields", http.StatusBadRequest)
			return
		}
		if err := s.changePersistentPassword(session.UserID, currentPassword, newPassword); err != nil {
			if errors.Is(err, errInvalidCredentials) {
				http.Error(responseWriter, "Invalid credentials", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, errWeakPassword) {
				http.Error(responseWriter, "New password is too weak", http.StatusBadRequest)
				return
			}
			http.Error(responseWriter, "Could not update profile", http.StatusInternalServerError)
			return
		}
		fmt.Fprint(responseWriter, "Password changed")
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

func safeWritableStaticFilePath(config Config.Settings, requestPath string) (string, error) {
	fileName, err := safePathUnderRoot(config.WEB_FILE_PATH, requestPath, config.WEB_INDEX_FILE, true)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errUnsafePath, err)
	}
	if err := validateExistingParentSymlinkSafe(config.WEB_FILE_PATH, fileName); err != nil {
		return "", fmt.Errorf("%w: %v", errUnsafePath, err)
	}
	return fileName, nil
}

func validateExistingParentSymlinkSafe(root, targetPath string) error {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	evaluatedRoot, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return err
	}
	parent := filepath.Dir(targetPath)
	for {
		if _, err := os.Lstat(parent); err == nil {
			break
		} else if errors.Is(err, os.ErrNotExist) {
			next := filepath.Dir(parent)
			if next == parent {
				return err
			}
			parent = next
		} else {
			return err
		}
	}
	evaluatedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	if !pathIsInsideRoot(evaluatedRoot, evaluatedParent) {
		return errUnsafePath
	}
	return nil
}

func (s siteService) canonicalRequestURIForFile(fileName string) (string, error) {
	rootPath, err := filepath.Abs(s.config.WEB_FILE_PATH)
	if err != nil {
		return "", err
	}
	targetPath, err := filepath.Abs(fileName)
	if err != nil {
		return "", err
	}
	if !pathIsInsideRoot(rootPath, targetPath) {
		return "", errUnsafePath
	}
	relativePath, err := filepath.Rel(rootPath, targetPath)
	if err != nil {
		return "", err
	}
	relativeSlash := filepath.ToSlash(relativePath)
	indexFile := s.config.WEB_INDEX_FILE
	if indexFile == "" {
		indexFile = "index.html"
	}
	if relativeSlash == indexFile {
		return "/", nil
	}
	if pathpkg.Base(relativeSlash) == indexFile {
		dir := pathpkg.Dir(relativeSlash)
		if dir == "." {
			return "/", nil
		}
		return "/" + strings.Trim(dir, "/") + "/", nil
	}
	return "/" + strings.TrimPrefix(relativeSlash, "/"), nil
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
		return "", errUnsafePath
	}
	if strings.HasPrefix(unescapedPath, "//") {
		return "", errUnsafePath
	}

	segments := strings.Split(unescapedPath, "/")
	for _, segment := range segments {
		if segment == ".." || strings.Contains(segment, ":") {
			return "", errUnsafePath
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
		return "", errUnsafePath
	}

	evaluatedRoot, err := filepath.EvalSymlinks(rootPath)
	if err == nil {
		if evaluatedTarget, err := filepath.EvalSymlinks(targetPath); err == nil && !pathIsInsideRoot(evaluatedRoot, evaluatedTarget) {
			return "", errUnsafePath
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

func trustedDBRevisionDomain(request *http.Request) (string, bool) {
	host, err := canonicalHostFromRequest(request)
	if err != nil {
		return defaultDBDomain, false
	}
	for _, allowedHost := range strings.Split(os.Getenv("SITEBRUSH_ALLOWED_HOSTS"), ",") {
		allowedHost = strings.TrimSpace(allowedHost)
		if allowedHost == "" {
			continue
		}
		canonicalAllowedHost, err := canonicalHost(allowedHost)
		if err != nil {
			log.Printf("SiteBrush ignoring invalid SITEBRUSH_ALLOWED_HOSTS entry %q: %v", allowedHost, err)
			continue
		}
		if canonicalAllowedHost == host {
			return host, true
		}
	}
	if isLocalDevHost(host) && isLoopbackRemoteAddr(request.RemoteAddr) {
		return host, true
	}
	return defaultDBDomain, false
}

func isLocalDevHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackRemoteAddr(remoteAddr string) bool {
	if remoteAddr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

func (s siteService) metadataPath(requestURI string) string {
	return filepath.Join(s.archiveRoot(), "metadata", safeArchiveName(requestURI)+".json")
}

func (s siteService) redirectsPath() string {
	return filepath.Join(s.archiveRoot(), "redirects.json")
}

func safeArchiveName(requestURI string) string {
	safeName := strings.Trim(strings.ReplaceAll(pathpkg.Clean("/"+strings.TrimPrefix(requestURI, "/")), "/", "_"), "_")
	if safeName == "" {
		safeName = "index"
	}
	sum := sha256.Sum256([]byte(pathpkg.Clean("/" + strings.TrimPrefix(requestURI, "/"))))
	return fmt.Sprintf("%s-%s", safeName, hex.EncodeToString(sum[:])[:12])
}

func (s siteService) loadSidecarMetadata(requestURI string) (pageMetadata, error) {
	metadata := pageMetadata{
		Path:      requestURI,
		Title:     titleFromRequestURI(requestURI),
		Status:    "active",
		Published: true,
	}
	data, err := os.ReadFile(s.metadataPath(requestURI))
	if errors.Is(err, os.ErrNotExist) {
		return metadata, nil
	}
	if err != nil {
		return pageMetadata{}, err
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return pageMetadata{}, err
	}
	if metadata.Path == "" {
		metadata.Path = requestURI
	}
	if metadata.Title == "" {
		metadata.Title = titleFromRequestURI(requestURI)
	}
	if metadata.Status == "" {
		metadata.Status = "active"
	}
	return metadata, nil
}

func (s siteService) loadPageMetadata(request *http.Request, requestURI string) (pageMetadata, error) {
	metadata, err := s.loadSidecarMetadata(requestURI)
	if err != nil {
		return pageMetadata{}, err
	}
	if !s.dbPostRevisionConfigured() {
		return metadata, nil
	}
	domain, trusted := trustedDBRevisionDomain(request)
	if !trusted {
		log.Printf("SiteBrush properties metadata using default domain for untrusted host %q", request.Host)
	}
	posts, err := Database.LoadPostRevisionsFromConfig(s.config, requestURI, domain)
	if err != nil {
		return pageMetadata{}, err
	}
	if len(posts) == 0 {
		return metadata, nil
	}
	latest := posts[len(posts)-1]
	if latest.Title != "" {
		metadata.Title = latest.Title
	}
	metadata.Tags = latest.Tags
	if latest.Status != "" {
		metadata.Status = latest.Status
	}
	metadata.Published = latest.Published
	return metadata, nil
}

func (s siteService) writePageMetadata(metadata pageMetadata) error {
	if metadata.Status == "" {
		metadata.Status = "active"
	}
	metadata.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.metadataPath(metadata.Path), data, 0o600)
}

func (s siteService) removePageMetadata(requestURI string) error {
	metadataPath := s.metadataPath(requestURI)
	if err := os.Remove(metadataPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(metadataPath))
}

func (s siteService) updateProperties(request *http.Request, currentFileName string) (string, error) {
	currentURI, err := s.canonicalRequestURIForFile(currentFileName)
	if err != nil {
		return "", err
	}
	newPath := strings.TrimSpace(request.FormValue("new_path"))
	if newPath == "" {
		newPath = currentURI
	}
	if !strings.HasPrefix(newPath, "/") {
		newPath = "/" + newPath
	}
	newFileName, err := safeWritableStaticFilePath(s.config, newPath)
	if err != nil {
		return "", err
	}
	newURI, err := s.canonicalRequestURIForFile(newFileName)
	if err != nil {
		return "", err
	}
	metadata := pageMetadata{
		Path:      newURI,
		Title:     strings.TrimSpace(request.FormValue("title")),
		Tags:      strings.TrimSpace(request.FormValue("tags")),
		Status:    strings.TrimSpace(request.FormValue("status")),
		Published: request.FormValue("published") != "",
	}
	if metadata.Title == "" {
		metadata.Title = titleFromRequestURI(newURI)
	}
	if metadata.Status == "" {
		metadata.Status = "active"
	}
	if err := s.writePageMetadata(metadata); err != nil {
		return "", err
	}
	if newURI != currentURI {
		renamed := false
		if err := s.renameStaticFile(currentFileName, newFileName); err != nil {
			if cleanupErr := s.removePageMetadata(newURI); cleanupErr != nil {
				return "", fmt.Errorf("rename failed after metadata write: %w; metadata cleanup failed: %v", err, cleanupErr)
			}
			return "", err
		}
		renamed = true
		domain, trusted := trustedDBRevisionDomain(request)
		if !trusted {
			log.Printf("SiteBrush redirect using default domain for untrusted host %q", request.Host)
		}
		redirect := Data.Redirect{
			OldUri: currentURI,
			NewUri: newURI,
			Date:   time.Now().UTC().UnixMilli(),
			Status: "active",
			Domain: domain,
		}
		if err := s.saveRedirect(redirect); err != nil {
			if renamed {
				if rollbackErr := s.renameStaticFile(newFileName, currentFileName); rollbackErr != nil {
					return "", fmt.Errorf("save redirect failed after rename: %w; rollback failed: %v", err, rollbackErr)
				}
			}
			if cleanupErr := s.removePageMetadata(newURI); cleanupErr != nil {
				return "", fmt.Errorf("save redirect failed after metadata write: %w; metadata cleanup failed: %v", err, cleanupErr)
			}
			return "", err
		}
	}
	return newURI, nil
}

func (s siteService) renameStaticFile(currentFileName, newFileName string) error {
	currentAbs, err := filepath.Abs(currentFileName)
	if err != nil {
		return err
	}
	newAbs, err := filepath.Abs(newFileName)
	if err != nil {
		return err
	}
	if currentAbs == newAbs {
		return nil
	}
	if err := validateExistingParentSymlinkSafe(s.config.WEB_FILE_PATH, newAbs); err != nil {
		return fmt.Errorf("%w: %v", errUnsafePath, err)
	}
	if _, err := os.Stat(newAbs); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(currentAbs); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newAbs), 0o755); err != nil {
		return err
	}
	if err := os.Rename(currentAbs, newAbs); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(newAbs)); err != nil {
		return rollbackRenameAfterSyncFailure(currentAbs, newAbs, err)
	}
	if filepath.Dir(currentAbs) != filepath.Dir(newAbs) {
		if err := syncDir(filepath.Dir(currentAbs)); err != nil {
			return rollbackRenameAfterSyncFailure(currentAbs, newAbs, err)
		}
	}
	return nil
}

func rollbackRenameAfterSyncFailure(currentAbs, newAbs string, syncErr error) error {
	if rollbackErr := os.Rename(newAbs, currentAbs); rollbackErr != nil {
		return fmt.Errorf("rename sync failed: %w; rollback failed: %v", syncErr, rollbackErr)
	}
	if err := syncDir(filepath.Dir(currentAbs)); err != nil {
		return fmt.Errorf("rename sync failed: %w; rollback sync failed: %v", syncErr, err)
	}
	if filepath.Dir(currentAbs) != filepath.Dir(newAbs) {
		if err := syncDir(filepath.Dir(newAbs)); err != nil {
			return fmt.Errorf("rename sync failed: %w; rollback cleanup sync failed: %v", syncErr, err)
		}
	}
	return syncErr
}

func (s siteService) loadRedirects() ([]Data.Redirect, error) {
	data, err := os.ReadFile(s.redirectsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var redirects []Data.Redirect
	if err := json.Unmarshal(data, &redirects); err != nil {
		return nil, err
	}
	return redirects, nil
}

func restoreRedirectsFile(redirectsPath string, previousContent []byte, existed bool) error {
	if existed {
		return atomicWriteFile(redirectsPath, previousContent, 0o600)
	}
	if err := os.Remove(redirectsPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(redirectsPath))
}

func (s siteService) saveRedirect(redirect Data.Redirect) error {
	redirectFileLock.Lock()
	defer redirectFileLock.Unlock()

	redirectsPath := s.redirectsPath()
	previousContent, readErr := os.ReadFile(redirectsPath)
	previousExisted := true
	if errors.Is(readErr, os.ErrNotExist) {
		previousExisted = false
	} else if readErr != nil {
		return readErr
	}
	redirects, err := s.loadRedirects()
	if err != nil {
		return err
	}
	replaced := false
	for i := range redirects {
		if redirects[i].OldUri == redirect.OldUri && redirects[i].Domain == redirect.Domain {
			redirects[i] = redirect
			replaced = true
			break
		}
	}
	if !replaced {
		redirects = append(redirects, redirect)
	}
	data, err := json.MarshalIndent(redirects, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(s.redirectsPath(), data, 0o600); err != nil {
		return err
	}
	if s.dbPostRevisionConfigured() {
		if _, err := Database.SaveRedirectFromConfig(s.config, redirect); err != nil {
			if rollbackErr := restoreRedirectsFile(redirectsPath, previousContent, previousExisted); rollbackErr != nil {
				return fmt.Errorf("database redirect save failed: %w; redirects rollback failed: %v", err, rollbackErr)
			}
			return err
		}
	}
	return nil
}

func (s siteService) findRedirect(request *http.Request, oldURI string) (Data.Redirect, bool, error) {
	domain, trusted := trustedDBRevisionDomain(request)
	if !trusted {
		log.Printf("SiteBrush redirect lookup using default domain for untrusted host %q", request.Host)
	}
	if s.dbPostRevisionConfigured() {
		redirect, ok, err := Database.LoadRedirectFromConfig(s.config, oldURI, domain)
		if err != nil {
			return Data.Redirect{}, false, err
		}
		if ok {
			return redirect, true, nil
		}
	}
	redirects, err := s.loadRedirects()
	if err != nil {
		return Data.Redirect{}, false, err
	}
	for _, redirect := range redirects {
		if redirect.OldUri == oldURI && redirect.Domain == domain && redirect.Status == "active" {
			return redirect, true, nil
		}
	}
	return Data.Redirect{}, false, nil
}

func validInternalRedirectTarget(target string) bool {
	if target == "" || !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return false
	}
	if strings.Contains(target, `\`) {
		return false
	}
	if strings.IndexFunc(target, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	if parsed.IsAbs() || parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") {
		return false
	}
	unescapedPath, err := url.PathUnescape(parsed.Path)
	if err != nil {
		return false
	}
	if strings.Contains(unescapedPath, `\`) {
		return false
	}
	if strings.HasPrefix(unescapedPath, "//") {
		return false
	}
	if strings.IndexFunc(unescapedPath, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return false
	}
	for _, segment := range strings.Split(unescapedPath, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}

func handleRequest(config Config.Settings, responseWriter http.ResponseWriter, request *http.Request) {
	service := siteService{config: config, sessions: defaultSessions}
	service.handle(responseWriter, request)
}

func (s siteService) handle(responseWriter http.ResponseWriter, request *http.Request) {
	if request.URL.Path == healthzPath {
		s.health(responseWriter, request)
		return
	}

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
		staticFileName := fileName
		if snapshotFileName, ok := s.snapshotFileForAnonymousRequest(request); ok {
			staticFileName = snapshotFileName
		}
		if checkFileExist(staticFileName) {
			http.ServeFile(responseWriter, request, staticFileName)
			return
		}
		requestURI, err := s.canonicalRequestURIForFile(fileName)
		if err != nil {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		redirect, ok, err := s.findRedirect(request, requestURI)
		if err != nil {
			http.Error(responseWriter, "Redirect lookup failed", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return
		}
		if !validInternalRedirectTarget(redirect.NewUri) {
			log.Printf("SiteBrush rejected unsafe redirect target for %q: %q", requestURI, redirect.NewUri)
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return
		}
		http.Redirect(responseWriter, request, redirect.NewUri, http.StatusMovedPermanently)
	case "login":
		s.login(responseWriter, request)
	case "edit":
		s.edit(responseWriter, request, fileName)
	case "delete":
		s.notImplementedMutation(responseWriter, request, "delete revision")
	case "revisions":
		s.revisions(responseWriter, request, fileName)
	case "subpages":
		s.subpages(responseWriter, request, fileName)
	case "properties":
		s.properties(responseWriter, request, fileName)
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
	case "health":
		s.health(responseWriter, request)
	case "join":
		s.join(responseWriter, request)
	case "recover":
		s.recover(responseWriter, request)
	case "verify", "captcha":
		s.notImplementedPublic(responseWriter, request, action)
	case "upload":
		s.upload(responseWriter, request)
	case "grab":
		s.grab(responseWriter, request, fileName)
	case "domains", "undelete":
		s.notImplementedMutation(responseWriter, request, action)
	default:
		http.Error(responseWriter, "Not Found", http.StatusNotFound)
	}
}

func (s siteService) health(responseWriter http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		responseWriter.Header().Set("Allow", "GET, HEAD")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	status := http.StatusOK
	body := healthResponse{Status: "ok"}
	if err := s.checkReadiness(); err != nil {
		status = http.StatusServiceUnavailable
		body.Status = "unavailable"
	}

	responseWriter.Header().Set("Cache-Control", "no-store")
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(responseWriter).Encode(body)
}

func (s siteService) checkReadiness() error {
	if err := ensureUsableDirectory(s.config.WEB_FILE_PATH); err != nil {
		return err
	}
	if err := ensureUsableDirectory(s.archiveRoot()); err != nil {
		return err
	}
	return nil
}

func ensureUsableDirectory(path string) error {
	if path == "" {
		path = "."
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("path is not a directory")
	}

	probePath := filepath.Join(path, fmt.Sprintf(".sitebrush-healthz-%d-%d", os.Getpid(), time.Now().UnixNano()))
	probe, err := os.OpenFile(probePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := probe.Write([]byte("ok\n")); err != nil {
		_ = probe.Close()
		_ = os.Remove(probePath)
		return err
	}
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		return err
	}
	return os.Remove(probePath)
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
		if snapshotFileName, ok := s.snapshotFileForAnonymousRequest(request); ok {
			fileName = snapshotFileName
		}
		if !checkFileExist(fileName) {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return true
		}
		http.ServeFile(responseWriter, request, fileName)
		return true
	case request.URL.Path == "/f" || strings.HasPrefix(request.URL.Path, "/f/"):
		mediaPath := strings.TrimPrefix(request.URL.Path, "/f")
		if mediaPath == "" || mediaPath == "/" {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return true
		}
		fileName := ""
		if snapshotFileName, ok := s.snapshotMediaFileForAnonymousRequest(request, mediaPath); ok {
			fileName = snapshotFileName
		} else {
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
			fileName, err = safePathUnderRoot(roots.MediaRoot, mediaPath, "", false)
			if err != nil {
				http.Error(responseWriter, "Forbidden", http.StatusForbidden)
				return true
			}
		}
		info, err := os.Stat(fileName)
		if err != nil {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return true
		}
		if info.IsDir() {
			http.Error(responseWriter, "Not Found", http.StatusNotFound)
			return true
		}
		responseWriter.Header().Set("X-Content-Type-Options", "nosniff")
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
		if key == "upload" {
			if len(value) > 1 {
				return "", errors.New("invalid query")
			}
			if len(value) == 1 && value[0] != "" && value[0] != "file" && value[0] != "image" {
				return "", errors.New("invalid query")
			}
			return key, nil
		}
		if len(value) > 1 || (len(value) == 1 && value[0] != "") {
			return "", errors.New("invalid query")
		}
		switch key {
		case "login", "edit", "delete", "revisions", "subpages", "properties", "freeze", "unfreeze", "backup", "profile", "logout", "health",
			"join", "verify", "recover", "grab", "domains", "undelete", "captcha":
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

func (s siteService) revisionLockKey(requestURI string) string {
	return filepath.Clean(s.revisionDir(requestURI))
}

func (s siteService) nextRevision(requestURI string) (int, error) {
	records, err := s.loadRevisions(requestURI)
	if err != nil {
		return 0, err
	}
	maxRevision := 0
	for _, record := range records {
		if record.Revision > maxRevision {
			maxRevision = record.Revision
		}
	}
	return maxRevision + 1, nil
}

func (s siteService) writeRevision(record revisionRecord) (string, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return "", err
	}
	dir := s.revisionDir(record.RequestURI)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	for attempt := 0; attempt < 16; attempt++ {
		suffix, err := randomRevisionSuffix()
		if err != nil {
			return "", err
		}
		name := fmt.Sprintf("%06d-%s-%s.json", record.Revision, record.CreatedAt.Format("20060102T150405.000000000Z"), suffix)
		revisionPath := filepath.Join(dir, name)
		reservation, err := os.OpenFile(revisionPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := reservation.Close(); err != nil {
			_ = os.Remove(revisionPath)
			return "", err
		}
		if err := atomicWriteFile(revisionPath, data, 0o600); err != nil {
			_ = os.Remove(revisionPath)
			return "", err
		}
		return revisionPath, nil
	}
	return "", errors.New("could not allocate unique revision filename")
}

func (s siteService) writeRevisionAtPath(record revisionRecord, revisionPath string) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(revisionPath, data, 0o600)
}

func randomRevisionSuffix() (string, error) {
	var buffer [8]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer[:]), nil
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

func (s siteService) loadDBRevisionMetadata(request *http.Request, requestURI string) ([]dbRevisionMetadata, error) {
	if !s.dbPostRevisionConfigured() {
		return nil, nil
	}
	domain, trusted := trustedDBRevisionDomain(request)
	if !trusted {
		log.Printf("SiteBrush DB revision metadata using default domain for untrusted host %q", request.Host)
	}
	posts, err := Database.LoadPostRevisionsFromConfig(s.config, requestURI, domain)
	if err != nil {
		return nil, err
	}
	records := make([]dbRevisionMetadata, 0, len(posts))
	for _, post := range posts {
		records = append(records, dbRevisionMetadata{
			Revision:   post.Revision,
			RequestURI: post.RequestUri,
			Domain:     post.Domain,
			Type:       post.Type,
			Title:      post.Title,
			Status:     post.Status,
			Published:  post.Published,
			CreatedAt:  time.UnixMilli(post.Date).UTC(),
		})
	}
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

func (s siteService) publishedRoot() string {
	return filepath.Join(s.archiveRoot(), "published")
}

func (s siteService) publishedMediaRoot(host string) string {
	return filepath.Join(s.publishedRoot(), ".sitebrush-media", "domains", host, "media")
}

func (s siteService) loadSiteState() (siteState, error) {
	data, err := os.ReadFile(s.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return siteState{}, nil
	}
	if err != nil {
		return siteState{}, err
	}
	var state siteState
	if err := json.Unmarshal(data, &state); err != nil {
		return siteState{}, err
	}
	return state, nil
}

func (s siteService) writeSiteState(state siteState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.statePath(), data, 0o600)
}

func (s siteService) snapshotFileForAnonymousRequest(request *http.Request) (string, bool) {
	if _, ok := s.sessions.get(request); ok {
		return "", false
	}
	state, err := s.loadSiteState()
	if err != nil || !state.Frozen {
		if err != nil {
			log.Printf("SiteBrush could not load freeze state: %v", err)
		}
		return "", false
	}
	fileName, err := safePathUnderRoot(s.publishedRoot(), request.URL.Path, s.config.WEB_INDEX_FILE, true)
	if err != nil {
		return "", false
	}
	return fileName, true
}

func (s siteService) snapshotMediaFileForAnonymousRequest(request *http.Request, mediaPath string) (string, bool) {
	if _, ok := s.sessions.get(request); ok {
		return "", false
	}
	state, err := s.loadSiteState()
	if err != nil || !state.Frozen {
		if err != nil {
			log.Printf("SiteBrush could not load freeze state: %v", err)
		}
		return "", false
	}
	host, err := canonicalHostFromRequest(request)
	if err != nil {
		return "", false
	}
	fileName, err := safePathUnderRoot(s.publishedMediaRoot(host), mediaPath, "", false)
	if err != nil {
		return "", false
	}
	return fileName, true
}

func (s siteService) publishSnapshot() error {
	rootPath, err := filepath.Abs(s.config.WEB_FILE_PATH)
	if err != nil {
		return err
	}
	publishedRoot, err := filepath.Abs(s.publishedRoot())
	if err != nil {
		return err
	}
	if pathIsInsideRoot(rootPath, publishedRoot) {
		return errors.New("published snapshot destination cannot be inside web root")
	}
	if err := os.MkdirAll(filepath.Dir(publishedRoot), 0o755); err != nil {
		return err
	}
	tmpRoot, err := os.MkdirTemp(filepath.Dir(publishedRoot), ".published-*")
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpRoot)
		}
	}()
	if err := copyDirectoryContents(rootPath, tmpRoot); err != nil {
		return err
	}
	if err := s.copyPublishedMediaSnapshots(tmpRoot); err != nil {
		return err
	}
	oldRoot := publishedRoot + ".old"
	_ = os.RemoveAll(oldRoot)
	if err := os.Rename(publishedRoot, oldRoot); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmpRoot, publishedRoot); err != nil {
		if restoreErr := os.Rename(oldRoot, publishedRoot); restoreErr != nil && !errors.Is(restoreErr, os.ErrNotExist) {
			return fmt.Errorf("publish snapshot failed: %w; restore failed: %v", err, restoreErr)
		}
		return err
	}
	cleanup = false
	if err := syncDir(filepath.Dir(publishedRoot)); err != nil {
		return err
	}
	if err := os.RemoveAll(oldRoot); err != nil {
		return err
	}
	return nil
}

func copyDirectoryContents(sourceRoot, targetRoot string) error {
	rootPath, err := filepath.Abs(sourceRoot)
	if err != nil {
		return err
	}
	if evaluatedRoot, err := filepath.EvalSymlinks(rootPath); err == nil {
		rootPath = evaluatedRoot
	}
	targetRoot, err = filepath.Abs(targetRoot)
	if err != nil {
		return err
	}
	return filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		absolutePath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if !pathIsInsideRoot(rootPath, absolutePath) {
			return errUnsafePath
		}
		relativePath, err := filepath.Rel(rootPath, absolutePath)
		if err != nil {
			return err
		}
		if relativePath == "." {
			return nil
		}
		targetPath := filepath.Join(targetRoot, relativePath)
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return os.MkdirAll(targetPath, 0o755)
		}
		return copyRegularFile(absolutePath, targetPath)
	})
}

func (s siteService) copyPublishedMediaSnapshots(targetPublishedRoot string) error {
	domainsRoot := filepath.Join(s.archiveRoot(), "domains")
	entries, err := os.ReadDir(domainsRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.Contains(entry.Name(), string(filepath.Separator)) {
			continue
		}
		sourceMediaRoot := filepath.Join(domainsRoot, entry.Name(), "media")
		if _, err := os.Stat(sourceMediaRoot); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		targetMediaRoot := filepath.Join(targetPublishedRoot, ".sitebrush-media", "domains", entry.Name(), "media")
		if err := copyDirectoryContents(sourceMediaRoot, targetMediaRoot); err != nil {
			return err
		}
	}
	return nil
}

func copyRegularFile(sourcePath, targetPath string) error {
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return errUnsafePath
	}
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	return nil
}

func (s siteService) createBackup() (backupRecord, error) {
	rootPath, err := filepath.Abs(s.config.WEB_FILE_PATH)
	if err != nil {
		return backupRecord{}, err
	}
	evaluatedRootPath, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return backupRecord{}, err
	}
	backupDir := filepath.Join(s.archiveRoot(), "backups")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return backupRecord{}, err
	}
	archiveRoot, err := filepath.Abs(s.archiveRoot())
	if err != nil {
		return backupRecord{}, err
	}
	evaluatedArchiveRoot, err := filepath.EvalSymlinks(archiveRoot)
	if err != nil {
		return backupRecord{}, err
	}
	absoluteBackupDir, err := filepath.Abs(backupDir)
	if err != nil {
		return backupRecord{}, err
	}
	evaluatedBackupDir, err := filepath.EvalSymlinks(absoluteBackupDir)
	if err != nil {
		return backupRecord{}, err
	}
	if pathIsInsideRoot(rootPath, absoluteBackupDir) ||
		pathIsInsideRoot(evaluatedRootPath, evaluatedArchiveRoot) ||
		pathIsInsideRoot(evaluatedRootPath, evaluatedBackupDir) {
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
	manifest := map[string]any{
		"format":              "sitebrush-v2-foundation",
		"created_at":          time.Now().UTC(),
		"web_prefix":          "web/",
		"archive_prefix":      "archive/",
		"database_restore":    "deferred",
		"auth_users_included": false,
	}
	if err := addJSONToZip(zipWriter, "sitebrush-backup.json", manifest); err != nil {
		_ = zipWriter.Close()
		_ = tmpFile.Close()
		return backupRecord{}, err
	}
	if err := addDirectoryToZip(zipWriter, rootPath, "web"); err != nil {
		_ = zipWriter.Close()
		_ = tmpFile.Close()
		return backupRecord{}, err
	}
	if err := s.addSafeArchiveMetadataToZip(zipWriter); err != nil {
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

	finalPath, err := reserveUniqueBackupPath(backupDir, time.Now().UTC())
	if err != nil {
		return backupRecord{}, err
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		_ = os.Remove(finalPath)
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

func addJSONToZip(zipWriter *zip.Writer, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	writer, err := zipWriter.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func reserveUniqueBackupPath(backupDir string, createdAt time.Time) (string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		suffix, err := randomRevisionSuffix()
		if err != nil {
			return "", err
		}
		name := fmt.Sprintf("sitebrush-backup-%s-%s.zip", createdAt.Format("20060102T150405Z"), suffix)
		path := filepath.Join(backupDir, name)
		reservation, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if err := reservation.Close(); err != nil {
			_ = os.Remove(path)
			return "", err
		}
		return path, nil
	}
	return "", errors.New("could not allocate unique backup filename")
}

func (s siteService) addSafeArchiveMetadataToZip(zipWriter *zip.Writer) error {
	archiveRoot, err := filepath.Abs(s.archiveRoot())
	if err != nil {
		return err
	}
	files := map[string]string{
		"site-state.json": s.statePath(),
		"redirects.json":  s.redirectsPath(),
	}
	for archiveName, sourcePath := range files {
		if err := addFileToZipIfExists(zipWriter, sourcePath, pathpkg.Join("archive", archiveName)); err != nil {
			return err
		}
	}
	for _, dir := range []string{"metadata", "templates"} {
		if err := addDirectoryToZipIfExists(zipWriter, filepath.Join(archiveRoot, dir), pathpkg.Join("archive", dir)); err != nil {
			return err
		}
	}
	domainsRoot := filepath.Join(archiveRoot, "domains")
	entries, err := os.ReadDir(domainsRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || strings.Contains(entry.Name(), string(filepath.Separator)) {
			continue
		}
		for _, dir := range []string{"media", "media-metadata"} {
			sourcePath := filepath.Join(domainsRoot, entry.Name(), dir)
			archivePrefix := pathpkg.Join("archive", "domains", entry.Name(), dir)
			if err := addDirectoryToZipIfExists(zipWriter, sourcePath, archivePrefix); err != nil {
				return err
			}
		}
	}
	return nil
}

func addDirectoryToZipIfExists(zipWriter *zip.Writer, root, archivePrefix string) error {
	if _, err := os.Stat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return addDirectoryToZip(zipWriter, root, archivePrefix)
}

func addFileToZipIfExists(zipWriter *zip.Writer, sourcePath, archivePath string) error {
	if _, err := os.Stat(sourcePath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return addFileToZip(zipWriter, sourcePath, archivePath)
}

func addDirectoryToZip(zipWriter *zip.Writer, root, archivePrefix string) error {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	return filepath.WalkDir(rootPath, func(path string, entry fs.DirEntry, walkErr error) error {
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
		archivePath := pathpkg.Join(archivePrefix, filepath.ToSlash(relativePath))
		return addFileToZip(zipWriter, absolutePath, archivePath)
	})
}

func addFileToZip(zipWriter *zip.Writer, sourcePath, archivePath string) error {
	writer, err := zipWriter.Create(archivePath)
	if err != nil {
		return err
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	_, err = io.Copy(writer, source)
	return err
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

func (s siteService) restoreBackup(backupPath string) (backupRecord, error) {
	backupPath = strings.TrimSpace(backupPath)
	if backupPath == "" {
		return backupRecord{}, errUnsafePath
	}
	backupRoot, err := filepath.Abs(filepath.Join(s.archiveRoot(), "backups"))
	if err != nil {
		return backupRecord{}, err
	}
	absoluteBackupPath, err := filepath.Abs(backupPath)
	if err != nil {
		return backupRecord{}, err
	}
	if !pathIsInsideRoot(backupRoot, absoluteBackupPath) {
		return backupRecord{}, errUnsafePath
	}
	backupInfo, err := os.Lstat(absoluteBackupPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return backupRecord{}, os.ErrNotExist
		}
		return backupRecord{}, err
	}
	if backupInfo.Mode()&os.ModeSymlink != 0 || !backupInfo.Mode().IsRegular() {
		return backupRecord{}, errUnsafePath
	}
	reader, err := zip.OpenReader(absoluteBackupPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return backupRecord{}, os.ErrNotExist
		}
		return backupRecord{}, err
	}
	defer reader.Close()
	if err := s.validateRestoreArchive(reader.File); err != nil {
		return backupRecord{}, err
	}
	targets, err := s.collectRestoreTargets(reader.File)
	if err != nil {
		return backupRecord{}, err
	}
	rollbackEntries := make([]restoreRollbackEntry, 0, len(targets))
	for _, target := range targets {
		rollbackEntry, err := captureRestoreRollbackEntry(target.Root, target.Path)
		if err != nil {
			return backupRecord{}, err
		}
		rollbackEntries = append(rollbackEntries, rollbackEntry)
	}
	restoreStarted := false
	rollbackOnError := func(restoreErr error) (backupRecord, error) {
		if restoreStarted {
			if rollbackErr := rollbackRestore(rollbackEntries); rollbackErr != nil {
				return backupRecord{}, fmt.Errorf("restore failed: %w; rollback failed: %v", restoreErr, rollbackErr)
			}
		}
		return backupRecord{}, restoreErr
	}
	for _, target := range targets {
		restoreStarted = true
		if err := restoreZipFile(target.File, target.Root, target.Path); err != nil {
			return rollbackOnError(err)
		}
	}
	checksum, size, err := fileChecksum(absoluteBackupPath)
	if err != nil {
		return rollbackOnError(err)
	}
	record := backupRecord{Path: absoluteBackupPath, Checksum: checksum, Size: size, CreatedAt: time.Now().UTC()}
	if err := s.recordBackup(record, "restored", ""); err != nil {
		return rollbackOnError(err)
	}
	return record, nil
}

func captureRestoreRollbackEntry(root, path string) (restoreRollbackEntry, error) {
	if err := validateRestoreTargetPath(root, path); err != nil {
		return restoreRollbackEntry{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		createdDirs, dirErr := missingParentDirs(root, path)
		if dirErr != nil {
			return restoreRollbackEntry{}, dirErr
		}
		return restoreRollbackEntry{Path: path, Root: root, CreatedDirs: createdDirs}, nil
	}
	if err != nil {
		return restoreRollbackEntry{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return restoreRollbackEntry{}, errUnsafePath
	}
	if !info.Mode().IsRegular() {
		return restoreRollbackEntry{}, errUnsafePath
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return restoreRollbackEntry{}, err
	}
	return restoreRollbackEntry{Path: path, Root: root, Exists: true, Content: content, Mode: info.Mode().Perm()}, nil
}

func rollbackRestore(entries []restoreRollbackEntry) error {
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if err := validateRestoreTargetPath(entry.Root, entry.Path); err != nil {
			return err
		}
		if entry.Exists {
			if err := atomicWriteFile(entry.Path, entry.Content, entry.Mode); err != nil {
				return err
			}
			continue
		}
		if err := os.Remove(entry.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, dir := range entry.CreatedDirs {
			if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, syscall.EEXIST) {
				return err
			}
		}
		if err := syncDir(filepath.Dir(entry.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func missingParentDirs(root, targetPath string) ([]string, error) {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	current, err := filepath.Abs(filepath.Dir(targetPath))
	if err != nil {
		return nil, err
	}
	dirs := []string{}
	for pathIsInsideRoot(rootPath, current) && current != rootPath {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, errUnsafePath
			}
			if !info.IsDir() {
				return nil, errUnsafePath
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		dirs = append(dirs, current)
		next := filepath.Dir(current)
		if next == current {
			break
		}
		current = next
	}
	return dirs, nil
}

func (s siteService) validateRestoreArchive(files []*zip.File) error {
	for _, file := range files {
		if err := validateBackupEntryName(file.Name); err != nil {
			return err
		}
		if file.FileInfo().Mode()&os.ModeSymlink != 0 {
			return errUnsafePath
		}
		if file.FileInfo().IsDir() {
			continue
		}
		targetPath, ok, err := s.restoreTargetForArchiveName(file.Name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		root, err := s.restoreRootForArchiveName(file.Name)
		if err != nil {
			return err
		}
		if err := validateRestoreTargetPath(root, targetPath); err != nil {
			return err
		}
	}
	return nil
}

func (s siteService) collectRestoreTargets(files []*zip.File) ([]restoreTarget, error) {
	targets := []restoreTarget{}
	seen := map[string]string{}
	for _, file := range files {
		if file.FileInfo().IsDir() || file.Name == "sitebrush-backup.json" {
			continue
		}
		targetPath, ok, err := s.restoreTargetForArchiveName(file.Name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		root, err := s.restoreRootForArchiveName(file.Name)
		if err != nil {
			return nil, err
		}
		if err := validateRestoreTargetPath(root, targetPath); err != nil {
			return nil, err
		}
		cleanTarget := filepath.Clean(targetPath)
		if previous, exists := seen[cleanTarget]; exists {
			return nil, fmt.Errorf("duplicate restore target %q and %q", previous, file.Name)
		}
		seen[cleanTarget] = file.Name
		targets = append(targets, restoreTarget{
			ArchiveName: file.Name,
			Path:        targetPath,
			Root:        root,
			File:        file,
		})
	}
	return targets, nil
}

func validateBackupEntryName(name string) error {
	if name == "" || strings.Contains(name, `\`) || strings.Contains(name, "\x00") {
		return errUnsafePath
	}
	if pathpkg.IsAbs(name) || filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return errUnsafePath
	}
	cleaned := pathpkg.Clean(name)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return errUnsafePath
	}
	if cleaned != strings.TrimSuffix(name, "/") {
		return errUnsafePath
	}
	return nil
}

func validateRestoreTargetPath(root, targetPath string) error {
	rootPath, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return err
	}
	if !pathIsInsideRoot(rootPath, targetAbs) {
		return errUnsafePath
	}
	if err := rejectSymlinkComponents(rootPath, targetAbs); err != nil {
		return err
	}
	evaluatedRoot, err := filepath.EvalSymlinks(rootPath)
	if err != nil {
		return err
	}
	existingParent, err := nearestExistingParent(filepath.Dir(targetAbs))
	if err != nil {
		return err
	}
	evaluatedParent, err := filepath.EvalSymlinks(existingParent)
	if err != nil {
		return err
	}
	if !pathIsInsideRoot(evaluatedRoot, evaluatedParent) {
		return errUnsafePath
	}
	return nil
}

func rejectSymlinkComponents(rootPath, targetAbs string) error {
	current := rootPath
	for {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errUnsafePath
		}
		if current == targetAbs {
			return nil
		}
		relative, err := filepath.Rel(current, targetAbs)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		nextName := strings.Split(relative, string(filepath.Separator))[0]
		if nextName == "" || nextName == "." || nextName == ".." {
			return errUnsafePath
		}
		next := filepath.Join(current, nextName)
		if next == current {
			return errUnsafePath
		}
		current = next
	}
	return nil
}

func nearestExistingParent(path string) (string, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Lstat(current); err == nil {
			return current, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		next := filepath.Dir(current)
		if next == current {
			return "", os.ErrNotExist
		}
		current = next
	}
}

func (s siteService) restoreTargetForArchiveName(name string) (string, bool, error) {
	if err := validateBackupEntryName(name); err != nil {
		return "", false, err
	}
	switch {
	case strings.HasPrefix(name, "web/"):
		relativePath := strings.TrimPrefix(name, "web/")
		targetPath, err := safeJoinUnderRoot(s.config.WEB_FILE_PATH, filepath.FromSlash(relativePath))
		return targetPath, true, err
	case name == "archive/site-state.json":
		return s.statePath(), true, nil
	case name == "archive/redirects.json":
		return s.redirectsPath(), true, nil
	case strings.HasPrefix(name, "archive/metadata/"),
		strings.HasPrefix(name, "archive/templates/"),
		strings.HasPrefix(name, "archive/domains/") && strings.Contains(name, "/media/"),
		strings.HasPrefix(name, "archive/domains/") && strings.Contains(name, "/media-metadata/"):
		relativePath := strings.TrimPrefix(name, "archive/")
		targetPath, err := safeJoinUnderRoot(s.archiveRoot(), filepath.FromSlash(relativePath))
		return targetPath, true, err
	default:
		return "", false, nil
	}
}

func (s siteService) restoreRootForArchiveName(name string) (string, error) {
	if err := validateBackupEntryName(name); err != nil {
		return "", err
	}
	switch {
	case strings.HasPrefix(name, "web/"):
		return s.config.WEB_FILE_PATH, nil
	case name == "archive/site-state.json",
		name == "archive/redirects.json",
		strings.HasPrefix(name, "archive/metadata/"),
		strings.HasPrefix(name, "archive/templates/"),
		strings.HasPrefix(name, "archive/domains/") && strings.Contains(name, "/media/"),
		strings.HasPrefix(name, "archive/domains/") && strings.Contains(name, "/media-metadata/"):
		return s.archiveRoot(), nil
	default:
		return "", errUnsafePath
	}
}

func restoreZipFile(file *zip.File, root, targetPath string) error {
	if file.FileInfo().Mode()&os.ModeSymlink != 0 {
		return errUnsafePath
	}
	if err := validateRestoreTargetPath(root, targetPath); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	if err := validateRestoreTargetPath(root, targetPath); err != nil {
		return err
	}
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	mode := file.FileInfo().Mode().Perm()
	if mode == 0 {
		mode = 0o644
	}
	if err := validateRestoreTargetPath(root, targetPath); err != nil {
		return err
	}
	return atomicWriteFile(targetPath, content, mode)
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

func (s siteService) listStaticPagesUnder(currentURI string) ([]string, error) {
	rootPath, err := filepath.Abs(s.config.WEB_FILE_PATH)
	if err != nil {
		return nil, err
	}
	prefix := subpagePrefix(currentURI)
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
			return errUnsafePath
		}
		uri, err := s.canonicalRequestURIForFile(absolutePath)
		if err != nil {
			return err
		}
		if uri == currentURI {
			return nil
		}
		if strings.HasPrefix(uri, prefix) {
			pages = append(pages, uri)
		}
		return nil
	})
	sort.Strings(pages)
	return pages, err
}

func subpagePrefix(currentURI string) string {
	if currentURI == "" || currentURI == "/" {
		return "/"
	}
	if strings.HasSuffix(currentURI, "/") {
		return currentURI
	}
	ext := pathpkg.Ext(currentURI)
	if ext != "" {
		return strings.TrimSuffix(currentURI, ext) + "/"
	}
	return strings.TrimRight(currentURI, "/") + "/"
}

func (s siteService) createSubpage(currentFileName, requestedPath, title string) error {
	requestedPath = strings.TrimSpace(requestedPath)
	if requestedPath == "" {
		return errUnsafePath
	}
	if containsPathTraversalSegment(requestedPath) {
		return errUnsafePath
	}
	if !strings.HasSuffix(requestedPath, ".html") && !strings.HasSuffix(requestedPath, "/") {
		requestedPath += ".html"
	}
	if !strings.HasPrefix(requestedPath, "/") {
		currentURI, err := s.canonicalRequestURIForFile(currentFileName)
		if err != nil {
			return err
		}
		requestedPath = pathpkg.Join(subpagePrefix(currentURI), requestedPath)
		if !strings.HasPrefix(requestedPath, "/") {
			requestedPath = "/" + requestedPath
		}
	}
	fileName, err := safeWritableStaticFilePath(s.config, requestedPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(fileName); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	title = strings.TrimSpace(title)
	if title == "" {
		uri, err := s.canonicalRequestURIForFile(fileName)
		if err != nil {
			return err
		}
		title = titleFromRequestURI(uri)
	}
	body := "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>" + template.HTMLEscapeString(title) + "</title></head><body><h1>" + template.HTMLEscapeString(title) + "</h1></body></html>\n"
	return atomicWriteFile(fileName, []byte(body), 0o644)
}

func containsPathTraversalSegment(path string) bool {
	unescapedPath, err := url.PathUnescape(path)
	if err != nil {
		return true
	}
	for _, segment := range strings.Split(unescapedPath, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
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
  <label>Email <input type="email" name="email" autocomplete="username"></label>
  <label>Password <input type="password" name="password" autocomplete="current-password"></label>
  <button type="submit">Log in</button>
</form>`

const joinFormTemplate = `
<p>Create the first persistent SiteBrush administrator. This form is available only while no persistent users exist and a bootstrap token is configured.</p>
<form method="post" action="/?join">
  <label>Bootstrap token <input type="password" name="bootstrap_token" autocomplete="one-time-code" required></label>
  <label>Email <input type="email" name="email" autocomplete="username" required></label>
  <label>Password <input type="password" name="password" autocomplete="new-password" minlength="8" required></label>
  <button type="submit">Create admin</button>
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
{{else}}<p>No revisions.</p>{{end}}
{{if .Data.DBRecords}}
<h2>Database-backed revisions</h2>
<ol>{{range .Data.DBRecords}}<li>DB Revision {{.Revision}} {{.Status}} {{if .Published}}published{{else}}unpublished{{end}} for {{.Domain}}{{.RequestURI}} type {{.Type}} at {{.CreatedAt}}</li>{{end}}</ol>
{{end}}`

const subpagesTemplate = `
<p>Current path: {{.Data.CurrentPath}}</p>
{{if .Data.Pages}}<ul>{{range .Data.Pages}}<li>{{.}}</li>{{end}}</ul>{{else}}<p>No pages found.</p>{{end}}
<form method="post" action="{{.Data.Action}}">
  <input type="hidden" name="csrf" value="{{.Data.CSRF}}">
  <label>New subpage path <input name="path" placeholder="child.html"></label>
  <label>Title <input name="title"></label>
  <button type="submit">Create subpage</button>
</form>
<p>Recursive subpage move/navigation metadata updates are deferred.</p>`

const propertiesTemplate = `
<p>Current path: {{.Data.Path}}</p>
<form method="post" action="{{.Data.Action}}">
  <input type="hidden" name="csrf" value="{{.Data.CSRF}}">
  <label>Title <input name="title" value="{{.Data.Title}}"></label>
  <label>Tags <input name="tags" value="{{.Data.Tags}}"></label>
  <label>Status <input name="status" value="{{.Data.Status}}"></label>
  <label>Published <input type="checkbox" name="published" value="1" {{if .Data.Published}}checked{{end}}></label>
  <label>New path <input name="new_path" value="{{.Data.NewPath}}"></label>
  <button type="submit">Save properties</button>
</form>`

const grabFormTemplate = `
<p>Import one remote HTML page into this SiteBrush page. Recursive asset fetching and template propagation are deferred for safety.</p>
<form method="post" action="{{.Data.Action}}">
  <input type="hidden" name="csrf" value="{{.Data.CSRF}}">
  <label>Remote URL <input type="url" name="url" placeholder="https://example.com/page.html" required></label>
  <label>Target path <input name="target_path" placeholder="leave blank for current page"></label>
  <button type="submit">Import HTML</button>
</form>`

const grabResultTemplate = `
<p>Imported {{.Data.ImportedURI}} from {{.Data.URL}}.</p>
{{if ne .Data.FinalURL .Data.URL}}<p>Final URL after redirects: {{.Data.FinalURL}}</p>{{end}}
{{if .Data.Templates}}<h2>Detected templates</h2><ul>{{range .Data.Templates}}<li>{{.Name}} via {{.Source}} on &lt;{{.Tag}}&gt;</li>{{end}}</ul>{{else}}<p>No SiteBrush template markers detected.</p>{{end}}
{{if .Data.Warnings}}<h2>Warnings</h2><ul>{{range .Data.Warnings}}<li>{{.}}</li>{{end}}</ul>{{end}}`

const profileTemplate = `
<p>User: {{.Data.User}}</p>
{{with .Data.Email}}<p>Email: {{.}}</p>{{end}}
<p>Auth source: {{.Data.Source}}</p>
<p>Session expires: {{.Data.Expires}}</p>
<p>Site root: {{.Data.Site}}</p>
{{if eq .Data.Source "persistent"}}
<h2>Change password</h2>
<form method="post" action="/?profile">
  <input type="hidden" name="csrf" value="{{.Data.CSRF}}">
  <label>Current password <input type="password" name="current_password" autocomplete="current-password"></label>
  <label>New password <input type="password" name="new_password" autocomplete="new-password" minlength="8"></label>
  <button type="submit">Change password</button>
</form>
{{else}}
<p>Environment admin profile changes are not implemented yet.</p>
{{end}}`

const logoutTemplate = `
<form method="post" action="/?logout"><input type="hidden" name="csrf" value="{{.Data.CSRF}}"><button type="submit">Log out</button></form>`
