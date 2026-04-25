package webserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	Data "sitebrush/pkg/data"
	Database "sitebrush/pkg/database"
	"strings"
	"sync"
	"time"
)

const (
	maxGrabResponseBytes      int64 = 1024 * 1024
	maxGrabRedirects                = 3
	grabTimeout                     = 5 * time.Second
	maxTemplateMarkersPerPage       = 100
	maxTemplateMarkerNameLen        = 64
)

var (
	errGrabUnsafeURL   = errors.New("unsafe grab url")
	errGrabNonHTML     = errors.New("grab response is not HTML")
	errGrabTooLarge    = errors.New("grab response exceeds size limit")
	defaultGrabOptions = grabFetchOptions{
		Timeout:          grabTimeout,
		MaxResponseBytes: maxGrabResponseBytes,
		MaxRedirects:     maxGrabRedirects,
		Resolver:         net.DefaultResolver,
	}
	templateTagPattern     = regexp.MustCompile(`(?is)<([a-z][a-z0-9:-]*)([^>]*)>`)
	templateAttrPattern    = regexp.MustCompile(`(?is)([a-z_:][-a-z0-9_:.]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>` + "`" + `]+)`)
	htmlTagPattern         = regexp.MustCompile(`(?is)<[^!][^>]*>`)
	htmlAttrPattern        = regexp.MustCompile(`(?is)\s+([a-z_:][-a-z0-9_:.]*)\s*=\s*("[^"]*"|'[^']*'|[^\s"'=<>` + "`" + `]+)`)
	activeElementPattern   = regexp.MustCompile(`(?is)<\s*script\b[^>]*>.*?<\s*/\s*script\s*>`)
	activeStartTagPattern  = regexp.MustCompile(`(?is)<\s*(script|iframe|object|embed|applet)\b[^>]*>`)
	baseTagPattern         = regexp.MustCompile(`(?is)<\s*base\b[^>]*>`)
	metaTagPattern         = regexp.MustCompile(`(?is)<\s*meta\b[^>]*>`)
	siteBrushTemplateClass = regexp.MustCompile(`(?i)(^|\s)SiteBrushTemplate([-\w]*)(\s|$)`)
	templateMarkerName     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)
)

type grabResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type grabFetchOptions struct {
	Timeout                      time.Duration
	MaxResponseBytes             int64
	MaxRedirects                 int
	Resolver                     grabResolver
	AllowPrivateNetworksForTests bool
}

type grabResult struct {
	URL         string
	FinalURL    string
	StatusCode  int
	Body        string
	Warnings    []string
	Templates   []templateMarker
	ImportedURI string
}

type templateMarker struct {
	Name       string            `json:"name"`
	Source     string            `json:"source"`
	Tag        string            `json:"tag"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type templateSidecar struct {
	RequestURI string           `json:"request_uri"`
	UpdatedAt  time.Time        `json:"updated_at"`
	Templates  []templateMarker `json:"templates"`
}

type validatedGrabURL struct {
	URL *url.URL
	IPs []net.IP
}

func (s siteService) grab(responseWriter http.ResponseWriter, request *http.Request, fileName string) {
	session, ok := s.requireAuth(responseWriter, request)
	if !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		renderHTML(responseWriter, "Grab remote page", grabFormTemplate, map[string]any{
			"Action": request.URL.Path + "?grab",
			"CSRF":   session.CSRFToken,
		})
	case http.MethodPost:
		if !s.validCSRF(request, session) {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		if err := request.ParseForm(); err != nil {
			http.Error(responseWriter, "Invalid grab request", http.StatusBadRequest)
			return
		}
		targetFile, err := s.grabTargetFile(fileName, request.FormValue("target_path"))
		if err != nil {
			http.Error(responseWriter, "Forbidden", http.StatusForbidden)
			return
		}
		result, err := s.importGrabbedPage(request, session, targetFile, request.FormValue("url"))
		if err != nil {
			writeGrabError(responseWriter, err)
			return
		}
		renderHTML(responseWriter, "Grab complete", grabResultTemplate, result)
	default:
		responseWriter.Header().Set("Allow", "GET, POST")
		http.Error(responseWriter, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s siteService) grabTargetFile(currentFileName, requestedPath string) (string, error) {
	requestedPath = strings.TrimSpace(requestedPath)
	if requestedPath == "" {
		return currentFileName, nil
	}
	if !strings.HasPrefix(requestedPath, "/") {
		requestedPath = "/" + requestedPath
	}
	return safeWritableStaticFilePath(s.config, requestedPath)
}

func (s siteService) importGrabbedPage(request *http.Request, session operatorSession, fileName, rawURL string) (grabResult, error) {
	fetched, err := fetchGrabHTML(request.Context(), rawURL, defaultGrabOptions)
	if err != nil {
		return grabResult{}, err
	}
	sanitizedBody := sanitizeImportedHTML(fetched.Body)
	if err := s.saveEditedFile(request, session, fileName, sanitizedBody); err != nil {
		return grabResult{}, err
	}
	requestURI, err := s.canonicalRequestURIForFile(fileName)
	if err != nil {
		return grabResult{}, err
	}
	templates := detectTemplateMarkers(sanitizedBody)
	if err := s.persistTemplateMarkers(request, requestURI, templates); err != nil {
		return grabResult{}, err
	}
	fetched.Body = sanitizedBody
	fetched.ImportedURI = requestURI
	fetched.Templates = templates
	fetched.Warnings = append(fetched.Warnings, "recursive asset fetching is deferred; external asset URLs were left unchanged")
	return fetched, nil
}

func fetchGrabHTML(ctx context.Context, rawURL string, options grabFetchOptions) (grabResult, error) {
	options = normalizeGrabOptions(options)
	validated, err := validateGrabURL(ctx, rawURL, options)
	if err != nil {
		return grabResult{}, err
	}
	resolvedHosts := map[string][]net.IP{validated.URL.Hostname(): validated.IPs}
	var resolvedHostsMu sync.Mutex
	client := &http.Client{
		Timeout: options.Timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				resolvedHostsMu.Lock()
				ips := resolvedHosts[host]
				resolvedHostsMu.Unlock()
				if len(ips) == 0 {
					return nil, fmt.Errorf("%w: host was not validated before dialing", errGrabUnsafeURL)
				}
				return (&net.Dialer{Timeout: options.Timeout}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= options.MaxRedirects {
				return errors.New("grab redirect limit exceeded")
			}
			validatedRedirect, err := validateGrabURL(req.Context(), req.URL.String(), options)
			if err != nil {
				return err
			}
			resolvedHostsMu.Lock()
			resolvedHosts[validatedRedirect.URL.Hostname()] = validatedRedirect.IPs
			resolvedHostsMu.Unlock()
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, validated.URL.String(), nil)
	if err != nil {
		return grabResult{}, err
	}
	req.Header.Set("User-Agent", "SiteBrush/2 grab")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := client.Do(req)
	if err != nil {
		return grabResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return grabResult{}, fmt.Errorf("grab failed with status %d", resp.StatusCode)
	}
	if !isHTMLContentType(resp.Header.Get("Content-Type")) {
		return grabResult{}, errGrabNonHTML
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, options.MaxResponseBytes+1))
	if err != nil {
		return grabResult{}, err
	}
	if int64(len(data)) > options.MaxResponseBytes {
		return grabResult{}, errGrabTooLarge
	}
	return grabResult{
		URL:        validated.URL.String(),
		FinalURL:   resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		Body:       string(data),
	}, nil
}

func normalizeGrabOptions(options grabFetchOptions) grabFetchOptions {
	if options.Timeout <= 0 {
		options.Timeout = grabTimeout
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = maxGrabResponseBytes
	}
	if options.MaxRedirects <= 0 {
		options.MaxRedirects = maxGrabRedirects
	}
	if options.Resolver == nil {
		options.Resolver = net.DefaultResolver
	}
	return options
}

func validateGrabURL(ctx context.Context, rawURL string, options grabFetchOptions) (validatedGrabURL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return validatedGrabURL{}, fmt.Errorf("%w: missing url", errGrabUnsafeURL)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return validatedGrabURL{}, fmt.Errorf("%w: %v", errGrabUnsafeURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return validatedGrabURL{}, fmt.Errorf("%w: unsupported scheme", errGrabUnsafeURL)
	}
	if parsed.User != nil {
		return validatedGrabURL{}, fmt.Errorf("%w: credentials are not allowed", errGrabUnsafeURL)
	}
	if parsed.Host == "" {
		return validatedGrabURL{}, fmt.Errorf("%w: missing host", errGrabUnsafeURL)
	}
	host := parsed.Hostname()
	if host == "" {
		return validatedGrabURL{}, fmt.Errorf("%w: missing host", errGrabUnsafeURL)
	}
	ips, err := resolveGrabHost(ctx, host, options)
	if err != nil {
		return validatedGrabURL{}, err
	}
	return validatedGrabURL{URL: parsed, IPs: ips}, nil
}

func resolveGrabHost(ctx context.Context, host string, options grabFetchOptions) ([]net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if err := validateGrabIP(ip, options); err != nil {
			return nil, err
		}
		return []net.IP{ip}, nil
	}
	ips, err := options.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: dns lookup failed", errGrabUnsafeURL)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: dns lookup returned no addresses", errGrabUnsafeURL)
	}
	resolved := make([]net.IP, 0, len(ips))
	for _, addr := range ips {
		if err := validateGrabIP(addr.IP, options); err != nil {
			return nil, err
		}
		resolved = append(resolved, addr.IP)
	}
	return resolved, nil
}

func validateGrabIP(ip net.IP, options grabFetchOptions) error {
	if ip == nil {
		return fmt.Errorf("%w: invalid ip", errGrabUnsafeURL)
	}
	if options.AllowPrivateNetworksForTests {
		return nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%w: invalid ip", errGrabUnsafeURL)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if !addr.IsGlobalUnicast() || grabSpecialUseIP(addr) {
		return fmt.Errorf("%w: non-public or special-use address is not allowed", errGrabUnsafeURL)
	}
	return nil
}

func grabSpecialUseIP(addr netip.Addr) bool {
	for _, prefix := range grabSpecialUsePrefixes() {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func grabSpecialUsePrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("::ffff:0:0/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:2::/48"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
}

func isHTMLContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	return mediaType == "text/html" || mediaType == "application/xhtml+xml"
}

func writeGrabError(responseWriter http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errGrabUnsafeURL):
		status = http.StatusBadRequest
	case errors.Is(err, errGrabNonHTML):
		status = http.StatusUnsupportedMediaType
	case errors.Is(err, errGrabTooLarge):
		status = http.StatusRequestEntityTooLarge
	default:
		status = http.StatusInternalServerError
	}
	http.Error(responseWriter, err.Error(), status)
}

// sanitizeImportedHTML is a conservative regex-based hardening pass for grabbed
// pages before they are written under the public static root. It intentionally
// does not claim complete HTML sanitizer parity: malformed markup, exotic parser
// edge cases, and CSS content are not fully normalized here. The foundation
// removes active elements, inline event handlers, dangerous URL schemes, base
// tags, and meta refresh redirects so imported pages are safer by default.
func sanitizeImportedHTML(input string) string {
	sanitized := activeElementPattern.ReplaceAllString(input, "")
	sanitized = activeStartTagPattern.ReplaceAllString(sanitized, "")
	sanitized = baseTagPattern.ReplaceAllString(sanitized, "")
	sanitized = metaTagPattern.ReplaceAllStringFunc(sanitized, func(tag string) string {
		if isMetaRefreshTag(tag) {
			return ""
		}
		return tag
	})
	return htmlTagPattern.ReplaceAllStringFunc(sanitized, func(tag string) string {
		return htmlAttrPattern.ReplaceAllStringFunc(tag, func(attr string) string {
			matches := htmlAttrPattern.FindStringSubmatch(attr)
			if len(matches) < 3 {
				return attr
			}
			name := strings.ToLower(matches[1])
			value := unquoteHTMLAttr(matches[2])
			if strings.HasPrefix(name, "on") {
				return ""
			}
			if dangerousImportedURLAttr(name, value) {
				return ""
			}
			return attr
		})
	})
}

func isMetaRefreshTag(tag string) bool {
	attrs := parseTemplateAttrs(tag)
	return strings.EqualFold(strings.TrimSpace(attrs["http-equiv"]), "refresh")
}

func unquoteHTMLAttr(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return html.UnescapeString(value)
}

func dangerousImportedURLAttr(name, value string) bool {
	switch name {
	case "href", "src", "action", "formaction", "xlink:href":
	default:
		return false
	}
	normalized := normalizeImportedURLForSafety(value)
	if strings.HasPrefix(normalized, "javascript:") || strings.HasPrefix(normalized, "data:") {
		return true
	}
	if name == "action" || name == "formaction" {
		return strings.HasPrefix(normalized, "http:") || strings.HasPrefix(normalized, "https:") || strings.HasPrefix(normalized, "//")
	}
	return false
}

func normalizeImportedURLForSafety(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if r <= ' ' || r == 0x7f {
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

func detectTemplateMarkers(html string) []templateMarker {
	matches := templateTagPattern.FindAllStringSubmatch(html, -1)
	markers := []templateMarker{}
	for _, match := range matches {
		if len(markers) >= maxTemplateMarkersPerPage {
			break
		}
		if len(match) < 3 {
			continue
		}
		attrs := parseTemplateAttrs(match[2])
		name, source := markerName(attrs)
		if name == "" {
			continue
		}
		markers = append(markers, templateMarker{
			Name:       name,
			Source:     source,
			Tag:        strings.ToLower(match[1]),
			Attributes: attrs,
		})
	}
	return markers
}

func parseTemplateAttrs(raw string) map[string]string {
	attrs := map[string]string{}
	for _, match := range templateAttrPattern.FindAllStringSubmatch(raw, -1) {
		if len(match) < 3 {
			continue
		}
		name := strings.ToLower(match[1])
		value := strings.TrimSpace(match[2])
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		attrs[name] = value
	}
	return attrs
}

func markerName(attrs map[string]string) (string, string) {
	if value, ok := attrs["data-sitebrush-template"]; ok {
		value = strings.TrimSpace(value)
		if value == "" {
			value = "sitebrush-template"
		}
		if validTemplateMarkerName(value) {
			return value, "data-sitebrush-template"
		}
		return "", ""
	}
	classValue := attrs["class"]
	for _, className := range strings.Fields(classValue) {
		if siteBrushTemplateClass.MatchString(className) && validTemplateMarkerName(className) {
			return className, "class"
		}
	}
	return "", ""
}

func validTemplateMarkerName(name string) bool {
	return len(name) > 0 && len(name) <= maxTemplateMarkerNameLen && templateMarkerName.MatchString(name)
}

func (s siteService) templateMetadataPath(requestURI string) string {
	return filepath.Join(s.archiveRoot(), "templates", safeArchiveName(requestURI)+".json")
}

func (s siteService) persistTemplateMarkers(request *http.Request, requestURI string, markers []templateMarker) error {
	sidecar := templateSidecar{
		RequestURI: requestURI,
		UpdatedAt:  time.Now().UTC(),
		Templates:  markers,
	}
	data, err := json.MarshalIndent(sidecar, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(s.templateMetadataPath(requestURI), data, 0o600); err != nil {
		return err
	}
	if len(markers) == 0 || !s.dbPostRevisionConfigured() {
		return nil
	}
	domain, trusted := trustedDBRevisionDomain(request)
	if !trusted {
		log.Printf("SiteBrush template metadata using default domain for untrusted host %q", request.Host)
	}
	for _, marker := range markers {
		markerData, err := json.Marshal(marker)
		if err != nil {
			return err
		}
		if _, err := Database.SaveTemplateFromConfig(s.config, Data.Template{
			Name:   marker.Name,
			Data:   string(markerData),
			Status: "active",
			Domain: domain,
		}); err != nil {
			return err
		}
	}
	return nil
}
