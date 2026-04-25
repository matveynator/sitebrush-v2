package webserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	Data "sitebrush/pkg/data"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	passwordHashAlgorithm     = "sb-pbkdf2-sha256"
	passwordHashVersion       = 1
	passwordHashIterations    = 120000
	passwordHashMaxIterations = 600000
	passwordSaltBytes         = 16
	passwordKeyBytes          = 32
	superuserGroupName        = "Superuser"
	recoveryTokenDuration     = time.Hour
)

var (
	errInvalidCredentials = errors.New("invalid credentials")
	errWeakPassword       = errors.New("weak password")
	authStoreMu           sync.Mutex
)

type persistentAuthStore struct {
	Users          []Data.User      `json:"users"`
	Groups         []Data.Group     `json:"groups"`
	UserGroups     []Data.UserGroup `json:"user_groups"`
	RecoveryTokens []recoveryToken  `json:"recovery_tokens"`
	UpdatedAt      time.Time        `json:"updated_at"`
}

type recoveryToken struct {
	UserId    int64     `json:"user_id"`
	TokenHash string    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

func (s siteService) authStorePath() string {
	return filepath.Join(s.archiveRoot(), "auth", "users.json")
}

func (s siteService) loadAuthStore() (persistentAuthStore, error) {
	data, err := os.ReadFile(s.authStorePath())
	if errors.Is(err, os.ErrNotExist) {
		return persistentAuthStore{}, nil
	}
	if err != nil {
		return persistentAuthStore{}, err
	}
	var store persistentAuthStore
	if err := json.Unmarshal(data, &store); err != nil {
		return persistentAuthStore{}, err
	}
	return store, nil
}

func (s siteService) saveAuthStore(store persistentAuthStore) error {
	store.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.authStorePath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	return atomicWriteFile(s.authStorePath(), data, 0o600)
}

func (s siteService) hasPersistentUsers() (bool, error) {
	store, err := s.loadAuthStore()
	if err != nil {
		return false, err
	}
	return len(activeUsers(store.Users)) > 0, nil
}

func activeUsers(users []Data.User) []Data.User {
	active := make([]Data.User, 0, len(users))
	for _, user := range users {
		if user.Status == "" || user.Status == "active" {
			active = append(active, user)
		}
	}
	return active
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validEmail(email string) bool {
	if email == "" || len(email) > 254 || strings.ContainsAny(email, " \t\r\n") {
		return false
	}
	at := strings.LastIndex(email, "@")
	return at > 0 && at < len(email)-1 && strings.Contains(email[at+1:], ".")
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return errWeakPassword
	}
	return nil
}

func displayUserName(user Data.User) string {
	if user.Nickname != "" {
		return user.Nickname
	}
	if user.Email != "" {
		return user.Email
	}
	return fmt.Sprintf("user-%d", user.Id)
}

func (s siteService) authenticatePersistentUser(email, password string) (Data.User, bool, error) {
	authStoreMu.Lock()
	defer authStoreMu.Unlock()

	store, err := s.loadAuthStore()
	if err != nil {
		return Data.User{}, false, err
	}
	for i := range store.Users {
		if normalizeEmail(store.Users[i].Email) != email || (store.Users[i].Status != "" && store.Users[i].Status != "active") {
			continue
		}
		ok, err := verifyPassword(password, store.Users[i].PasswordHash)
		if err != nil {
			return Data.User{}, false, nil
		}
		if ok {
			store.Users[i].LastVisitTime = time.Now().UTC().Unix()
			if err := s.saveAuthStore(store); err != nil {
				return Data.User{}, false, err
			}
			return store.Users[i], true, nil
		}
		return Data.User{}, false, nil
	}
	return Data.User{}, false, nil
}

func (s siteService) changePersistentPassword(userID int64, currentPassword, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	authStoreMu.Lock()
	defer authStoreMu.Unlock()

	store, err := s.loadAuthStore()
	if err != nil {
		return err
	}
	for i := range store.Users {
		if store.Users[i].Id != userID || (store.Users[i].Status != "" && store.Users[i].Status != "active") {
			continue
		}
		ok, err := verifyPassword(currentPassword, store.Users[i].PasswordHash)
		if err != nil || !ok {
			return errInvalidCredentials
		}
		hash, err := hashPassword(newPassword)
		if err != nil {
			return err
		}
		store.Users[i].PasswordHash = hash
		return s.saveAuthStore(store)
	}
	return errInvalidCredentials
}

func (s siteService) createRecoveryToken(userID int64, expiresAt time.Time) (string, error) {
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(recoveryTokenDuration)
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	authStoreMu.Lock()
	defer authStoreMu.Unlock()

	store, err := s.loadAuthStore()
	if err != nil {
		return "", err
	}
	store.RecoveryTokens = append(store.RecoveryTokens, recoveryToken{
		UserId:    userID,
		TokenHash: hashToken(token),
		ExpiresAt: expiresAt.UTC(),
	})
	if err := s.saveAuthStore(store); err != nil {
		return "", err
	}
	return token, nil
}

func (s siteService) verifyRecoveryToken(userID int64, token string, now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	authStoreMu.Lock()
	defer authStoreMu.Unlock()

	store, err := s.loadAuthStore()
	if err != nil {
		return false
	}
	tokenHash := hashToken(token)
	for i := range store.RecoveryTokens {
		if store.RecoveryTokens[i].UserId != userID || !store.RecoveryTokens[i].UsedAt.IsZero() || now.After(store.RecoveryTokens[i].ExpiresAt) {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(store.RecoveryTokens[i].TokenHash), []byte(tokenHash)) == 1 {
			store.RecoveryTokens[i].UsedAt = now.UTC()
			return s.saveAuthStore(store) == nil
		}
	}
	return false
}

func (s siteService) createFirstAdmin(email, password string) (Data.User, error) {
	email = normalizeEmail(email)
	if !validEmail(email) {
		return Data.User{}, errors.New("invalid email")
	}
	if err := validatePassword(password); err != nil {
		return Data.User{}, err
	}
	authStoreMu.Lock()
	defer authStoreMu.Unlock()

	store, err := s.loadAuthStore()
	if err != nil {
		return Data.User{}, err
	}
	if len(activeUsers(store.Users)) > 0 {
		return Data.User{}, errors.New("users already exist")
	}
	passwordHash, err := hashPassword(password)
	if err != nil {
		return Data.User{}, err
	}
	now := time.Now().UTC()
	user := Data.User{
		Id:                 1,
		Email:              email,
		PasswordHash:       passwordHash,
		Nickname:           email,
		DateOfRegistration: now.Unix(),
		LastVisitTime:      now.Unix(),
		Activated:          "yes",
		Status:             "active",
		Language:           "en",
	}
	group := Data.Group{
		Id:      1,
		OwnerId: user.Id,
		Name:    superuserGroupName,
		Title:   superuserGroupName,
		Date:    now.Unix(),
		Status:  "active",
	}
	userGroup := Data.UserGroup{
		UserId:  user.Id,
		GroupId: group.Id,
		Status:  "active",
	}
	store.Users = []Data.User{user}
	store.Groups = []Data.Group{group}
	store.UserGroups = []Data.UserGroup{userGroup}
	if err := s.saveAuthStore(store); err != nil {
		return Data.User{}, err
	}
	return user, nil
}

func (s siteService) join(responseWriter http.ResponseWriter, request *http.Request) {
	hasUsers, err := s.hasPersistentUsers()
	if err != nil {
		http.Error(responseWriter, "Could not load user store", http.StatusInternalServerError)
		return
	}
	if hasUsers {
		http.Error(responseWriter, "First admin already exists", http.StatusForbidden)
		return
	}
	switch request.Method {
	case http.MethodGet:
		renderHTML(responseWriter, "Create first admin", joinFormTemplate, nil)
	case http.MethodPost:
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid join request", http.StatusBadRequest)
			return
		}
		user, err := s.createFirstAdmin(request.FormValue("email"), request.FormValue("password"))
		if err != nil {
			status := http.StatusBadRequest
			if err.Error() == "users already exist" {
				status = http.StatusForbidden
			}
			http.Error(responseWriter, err.Error(), status)
			return
		}
		if _, err := s.sessions.createForUser(responseWriter, request, displayUserName(user), user.Email, user.Id, "persistent"); err != nil {
			http.Error(responseWriter, "Could not create session", http.StatusInternalServerError)
			return
		}
		http.Redirect(responseWriter, request, "/?profile", http.StatusSeeOther)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s siteService) recover(responseWriter http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet, http.MethodPost:
		http.Error(responseWriter, "Password recovery token storage is implemented, but email delivery is not implemented yet", http.StatusNotImplemented)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, passwordSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived := pbkdf2HMACSHA256([]byte(password), salt, passwordHashIterations, passwordKeyBytes)
	return fmt.Sprintf("%s$v=%d$i=%d$s=%s$h=%s",
		passwordHashAlgorithm,
		passwordHashVersion,
		passwordHashIterations,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(derived),
	), nil
}

func verifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != passwordHashAlgorithm {
		return false, errors.New("unsupported password hash")
	}
	version, err := parsePasswordHashInt(parts[1], "v")
	if err != nil || version != passwordHashVersion {
		return false, errors.New("unsupported password hash version")
	}
	iterations, err := parsePasswordHashInt(parts[2], "i")
	if err != nil || iterations < 10000 || iterations > passwordHashMaxIterations {
		return false, errors.New("invalid password hash iterations")
	}
	salt, err := parsePasswordHashBytes(parts[3], "s")
	if err != nil || len(salt) < passwordSaltBytes {
		return false, errors.New("invalid password hash salt")
	}
	want, err := parsePasswordHashBytes(parts[4], "h")
	if err != nil || len(want) == 0 {
		return false, errors.New("invalid password hash")
	}
	got := pbkdf2HMACSHA256([]byte(password), salt, iterations, len(want))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, nil
	}
	return true, nil
}

func parsePasswordHashInt(part, key string) (int, error) {
	prefix := key + "="
	if !strings.HasPrefix(part, prefix) {
		return 0, errors.New("invalid password hash field")
	}
	return strconv.Atoi(strings.TrimPrefix(part, prefix))
}

func parsePasswordHashBytes(part, key string) ([]byte, error) {
	prefix := key + "="
	if !strings.HasPrefix(part, prefix) {
		return nil, errors.New("invalid password hash field")
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimPrefix(part, prefix))
}

func pbkdf2HMACSHA256(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	blocks := (keyLen + hashLen - 1) / hashLen
	output := make([]byte, 0, blocks*hashLen)
	for block := 1; block <= blocks; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var blockIndex [4]byte
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))
		_, _ = mac.Write(blockIndex[:])
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iterations; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		output = append(output, t...)
	}
	return output[:keyLen]
}
