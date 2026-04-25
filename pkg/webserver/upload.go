package webserver

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	Data "sitebrush/pkg/data"
	Database "sitebrush/pkg/database"
	"strings"
	"time"
	"unicode"
)

const maxUploadBytes int64 = 10 * 1024 * 1024

var (
	errUploadTooLarge    = errors.New("upload exceeds size limit")
	errUploadMissingFile = errors.New("missing upload file")
	errUploadNotAllowed  = errors.New("file type is not allowed")
)

type uploadResponse struct {
	Uploaded int      `json:"uploaded"`
	URL      string   `json:"url,omitempty"`
	FileName string   `json:"fileName,omitempty"`
	Size     int64    `json:"size,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type mediaSidecarMetadata struct {
	Type             string    `json:"type"`
	Hash             string    `json:"hash"`
	OriginalHash     string    `json:"original_hash"`
	Format           string    `json:"format"`
	MimeType         string    `json:"mime_type"`
	StoragePath      string    `json:"storage_path"`
	OriginalFileName string    `json:"original_file_name"`
	SafeFileName     string    `json:"safe_file_name"`
	Width            int       `json:"width,omitempty"`
	Height           int       `json:"height,omitempty"`
	BytesUsed        int64     `json:"bytes_used"`
	Domain           string    `json:"domain"`
	Status           string    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	Warnings         []string  `json:"warnings,omitempty"`
}

type uploadValidation struct {
	kind     string
	ext      string
	mimeType string
	width    int
	height   int
}

func (s siteService) upload(responseWriter http.ResponseWriter, request *http.Request) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	if request.Method != http.MethodPost {
		responseWriter.Header().Set("Allow", "POST")
		writeUploadJSON(responseWriter, http.StatusMethodNotAllowed, uploadResponse{Uploaded: 0, Error: "method not allowed"})
		return
	}
	if !validUploadCSRF(request, session) {
		writeUploadJSON(responseWriter, http.StatusForbidden, uploadResponse{Uploaded: 0, Error: "forbidden"})
		return
	}

	uploadKind := uploadKindFromRequest(request)
	if uploadKind != "file" && uploadKind != "image" {
		writeUploadJSON(responseWriter, http.StatusBadRequest, uploadResponse{Uploaded: 0, Error: "invalid upload type"})
		return
	}

	result, err := s.saveUploadedMedia(responseWriter, request, uploadKind)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, errUploadTooLarge):
			status = http.StatusRequestEntityTooLarge
		case strings.Contains(err.Error(), "database media metadata"):
			status = http.StatusInternalServerError
		case strings.Contains(err.Error(), "write media"):
			status = http.StatusInternalServerError
		}
		writeUploadJSON(responseWriter, status, uploadResponse{Uploaded: 0, Error: err.Error()})
		return
	}
	writeUploadJSON(responseWriter, http.StatusOK, result)
}

func validUploadCSRF(request *http.Request, session operatorSession) bool {
	token := request.Header.Get("X-CSRF-Token")
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(session.CSRFToken)) == 1
}

func uploadKindFromRequest(request *http.Request) string {
	values := request.URL.Query()["upload"]
	if len(values) == 0 {
		return ""
	}
	if values[0] == "" {
		return "file"
	}
	return values[0]
}

func (s siteService) saveUploadedMedia(responseWriter http.ResponseWriter, request *http.Request, uploadKind string) (uploadResponse, error) {
	request.Body = http.MaxBytesReader(responseWriter, request.Body, maxUploadBytes+(1<<20))
	reader, err := request.MultipartReader()
	if err != nil {
		return uploadResponse{}, fmt.Errorf("invalid multipart upload: %w", err)
	}

	part, fileName, err := nextUploadPart(reader)
	if err != nil {
		return uploadResponse{}, err
	}
	defer part.Close()

	content, err := readUploadPart(part)
	if err != nil {
		return uploadResponse{}, err
	}
	validation, err := validateUploadContent(uploadKind, fileName, content)
	if err != nil {
		return uploadResponse{}, err
	}

	host, err := canonicalHostFromRequest(request)
	if err != nil {
		return uploadResponse{}, fmt.Errorf("invalid upload host: %w", err)
	}
	roots, err := s.domainPaths(host)
	if err != nil {
		return uploadResponse{}, fmt.Errorf("invalid upload domain: %w", err)
	}

	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	storedName := hash + validation.ext
	storagePath := "/f/" + storedName
	targetPath, err := safeJoinUnderRoot(roots.MediaRoot, storedName)
	if err != nil {
		return uploadResponse{}, err
	}
	mediaPreexisting := pathExists(targetPath)
	if err := atomicWriteFile(targetPath, content, 0o644); err != nil {
		return uploadResponse{}, fmt.Errorf("write media file: %w", err)
	}

	sidecarPath, err := s.mediaSidecarPath(roots, storedName)
	if err != nil {
		cleanupWrittenUpload(targetPath, "", mediaPreexisting, true)
		return uploadResponse{}, fmt.Errorf("resolve media sidecar: %w", err)
	}
	sidecarPreexisting := pathExists(sidecarPath)

	warnings := []string{}
	if !s.dbPostRevisionConfigured() {
		warnings = append(warnings, "database is not configured; media metadata stored in sidecar only")
	}
	safeName := sanitizeUploadFileName(fileName)
	now := time.Now().UTC()
	metadata := mediaSidecarMetadata{
		Type:             validation.kind,
		Hash:             hash,
		OriginalHash:     hash,
		Format:           strings.TrimPrefix(validation.ext, "."),
		MimeType:         validation.mimeType,
		StoragePath:      storagePath,
		OriginalFileName: safeName,
		SafeFileName:     safeName,
		Width:            validation.width,
		Height:           validation.height,
		BytesUsed:        int64(len(content)),
		Domain:           host,
		Status:           "active",
		CreatedAt:        now,
		Warnings:         warnings,
	}
	if err := s.writeMediaSidecar(sidecarPath, metadata); err != nil {
		cleanupWrittenUpload(targetPath, "", mediaPreexisting, true)
		return uploadResponse{}, fmt.Errorf("write media sidecar: %w", err)
	}

	if s.dbPostRevisionConfigured() {
		media := Data.Media{
			Type:         validation.kind,
			Hash:         hash,
			OriginalHash: hash,
			Format:       strings.TrimPrefix(validation.ext, "."),
			MimeType:     validation.mimeType,
			StoragePath:  storagePath,
			Width:        validation.width,
			Height:       validation.height,
			Status:       "active",
			Domain:       host,
			Day:          now.YearDay(),
			Date:         now.UnixMilli(),
			BytesUsed:    int64(len(content)),
		}
		if _, err := Database.SaveMediaFromConfig(s.config, media); err != nil {
			cleanupWrittenUpload(targetPath, sidecarPath, mediaPreexisting, sidecarPreexisting)
			return uploadResponse{}, fmt.Errorf("database media metadata was not saved: %w", err)
		}
	}

	return uploadResponse{
		Uploaded: 1,
		URL:      storagePath,
		FileName: safeName,
		Size:     int64(len(content)),
		Warnings: warnings,
	}, nil
}

func nextUploadPart(reader *multipart.Reader) (*multipart.Part, string, error) {
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			return nil, "", errUploadMissingFile
		}
		if err != nil {
			return nil, "", err
		}
		name := part.FormName()
		if name != "upload" && name != "file" {
			part.Close()
			continue
		}
		if part.FileName() == "" {
			part.Close()
			continue
		}
		return part, part.FileName(), nil
	}
}

func readUploadPart(part io.Reader) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(part, maxUploadBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > maxUploadBytes {
		return nil, errUploadTooLarge
	}
	if len(content) == 0 {
		return nil, errors.New("empty upload")
	}
	return content, nil
}

func validateUploadContent(uploadKind, fileName string, content []byte) (uploadValidation, error) {
	ext := strings.ToLower(filepath.Ext(fileName))
	if ext == "" {
		return uploadValidation{}, errUploadNotAllowed
	}
	if rejectedUploadExtension(ext) {
		return uploadValidation{}, errUploadNotAllowed
	}
	sniffed := http.DetectContentType(content)
	if uploadKind == "image" {
		return validateImageUpload(ext, sniffed, content)
	}
	return validateFileUpload(ext, sniffed)
}

func validateImageUpload(ext, sniffed string, content []byte) (uploadValidation, error) {
	expected := map[string]string{
		".gif":  "image/gif",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
	}
	want, ok := expected[ext]
	if !ok || sniffed != want {
		return uploadValidation{}, errUploadNotAllowed
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(content))
	if err != nil {
		return uploadValidation{}, errUploadNotAllowed
	}
	if format == "jpeg" && (ext == ".jpg" || ext == ".jpeg") {
		return uploadValidation{kind: "image", ext: ext, mimeType: want, width: config.Width, height: config.Height}, nil
	}
	if "."+format != ext {
		return uploadValidation{}, errUploadNotAllowed
	}
	return uploadValidation{kind: "image", ext: ext, mimeType: want, width: config.Width, height: config.Height}, nil
}

func validateFileUpload(ext, sniffed string) (uploadValidation, error) {
	allowed := map[string][]string{
		".csv":  {"text/plain; charset=utf-8"},
		".json": {"text/plain; charset=utf-8", "application/json"},
		".md":   {"text/plain; charset=utf-8"},
		".pdf":  {"application/pdf"},
		".txt":  {"text/plain; charset=utf-8"},
	}
	mimes, ok := allowed[ext]
	if !ok {
		return uploadValidation{}, errUploadNotAllowed
	}
	for _, allowedMime := range mimes {
		if sniffed == allowedMime {
			return uploadValidation{kind: "file", ext: ext, mimeType: sniffed}, nil
		}
	}
	return uploadValidation{}, errUploadNotAllowed
}

func rejectedUploadExtension(ext string) bool {
	switch ext {
	case ".html", ".htm", ".js", ".css",
		".svg", ".svgz", ".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".com", ".msi", ".sh", ".bash", ".zsh", ".fish",
		".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".apk", ".iso":
		return true
	default:
		return false
	}
}

func sanitizeUploadFileName(fileName string) string {
	base := pathpkg.Base(filepath.ToSlash(fileName))
	base = strings.TrimSpace(base)
	if base == "." || base == "/" || base == "" {
		base = "upload"
	}
	var builder strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			builder.WriteRune(r)
		case unicode.IsSpace(r):
			builder.WriteRune('-')
		}
	}
	safe := strings.Trim(builder.String(), ".-")
	if safe == "" {
		return "upload"
	}
	if len(safe) > 128 {
		ext := filepath.Ext(safe)
		stem := strings.TrimSuffix(safe, ext)
		if len(ext) > 16 {
			ext = ""
		}
		if len(stem) > 128-len(ext) {
			stem = stem[:128-len(ext)]
		}
		safe = stem + ext
	}
	return safe
}

func (s siteService) mediaSidecarPath(roots domainPaths, storedName string) (string, error) {
	sidecarRoot, err := safeJoinUnderRoot(roots.ArchiveRoot, "media-metadata")
	if err != nil {
		return "", err
	}
	return safeJoinUnderRoot(sidecarRoot, storedName+".json")
}

func (s siteService) writeMediaSidecar(sidecarPath string, metadata mediaSidecarMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(sidecarPath, data, 0o600)
}

func cleanupWrittenUpload(mediaPath, sidecarPath string, mediaPreexisting, sidecarPreexisting bool) {
	if sidecarPath != "" && !sidecarPreexisting {
		_ = os.Remove(sidecarPath)
	}
	if mediaPath != "" && !mediaPreexisting {
		_ = os.Remove(mediaPath)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeUploadJSON(responseWriter http.ResponseWriter, status int, response uploadResponse) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	_ = json.NewEncoder(responseWriter).Encode(response)
}
