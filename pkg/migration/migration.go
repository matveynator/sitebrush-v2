package migration

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"

	Data "sitebrush/pkg/data"
)

const (
	WarningLegacyPassword      = "legacy_password_forced_reset"
	WarningInvalidInteger      = "invalid_integer"
	WarningUnsafeMediaLocation = "unsafe_media_location"
	WarningMissingDomain       = "missing_domain"
	WarningDomainMismatch      = "domain_mismatch"
)

type SourceData struct {
	Domains       []V1Domain
	Posts         []V1Post
	URIs          []V1URI
	Users         []V1User
	Groups        []V1Group
	UserGroups    []V1UserGroup
	Media         []V1Media
	Templates     []V1Template
	PostTemplates []V1PostTemplate
}

type ImportPlan struct {
	Domains       []Data.Domain
	Posts         []Data.Post
	Redirects     []Data.Redirect
	URIMaps       []Data.URIMap
	Users         []Data.User
	Groups        []Data.Group
	UserGroups    []Data.UserGroup
	Media         []Data.Media
	Templates     []Data.Template
	PostTemplates []Data.PostTemplate
	Warnings      []Warning
}

type Warning struct {
	Code     string
	Entity   string
	EntityID int64
	Field    string
	Message  string
}

type V1Domain struct {
	ID          int64
	Name        string
	DNSZoneData string
	CNAMESecret string
	Status      string
	EmailSecret string
	Freezed     int
}

type V1Post struct {
	ID         int64
	OwnerID    int
	DeleterID  int
	RequestURI string
	Type       string
	Date       int64
	Title      string
	Text       string
	ShortText  string
	Tags       string
	Version    int
	Domain     string
	Status     string
	Published  string
}

type V1URI struct {
	ID     int64
	OldURI string
	NewURI string
	Date   int64
	Status string
	Domain string
}

type V1User struct {
	ID                 int64
	SessionID          string
	OldID              int64
	AvatarID           int64
	Email              string
	Password           string
	Nickname           string
	FirstName          string
	LastName           string
	Gender             string
	Phone              string
	DateOfRegistration int64
	DateOfBirth        int64
	LastVisitTime      int64
	GrinvichTimeOffset int
	Activated          string
	VerificationCode   string
	Domain             string
	Status             string
	Language           string
	CurrentIP          string
	Profile            string
	Preferences        string
	SecurityLog        string
	InvitedBy          string
	InvitesAmmount     int
	QuotaBytes         string
	QuotaOriginals     string
	QuotaBytesUsed     int64
	QuotaOriginalsUsed int64
	AutoGrab           string
	DomainToGrab       string
}

type V1Group struct {
	ID      int64
	OwnerID int64
	Name    string
	Title   string
	Comment string
	Date    int64
	Status  string
	Domain  string
}

type V1UserGroup struct {
	UserID  int64
	GroupID int64
}

type V1Media struct {
	ID           int64
	Type         string
	Hash         string
	OriginalHash string
	Format       string
	Width        string
	Height       string
	Status       string
	Domain       string
	Day          int
	Date         int64
	SizesArray   string
	Rating       float64
	RatingCount  int
	RatingIP     string
	Views        int
	BytesUsed    int64
}

type V1Template struct {
	ID     int64
	Name   string
	Data   string
	Status string
	Domain string
}

type V1PostTemplate struct {
	PostID     int64
	TemplateID int64
}

func BuildImportPlan(source SourceData) ImportPlan {
	plan := ImportPlan{
		Domains:       make([]Data.Domain, 0, len(source.Domains)),
		Posts:         make([]Data.Post, 0, len(source.Posts)),
		Redirects:     make([]Data.Redirect, 0, len(source.URIs)),
		URIMaps:       make([]Data.URIMap, 0, len(source.URIs)),
		Users:         make([]Data.User, 0, len(source.Users)),
		Groups:        make([]Data.Group, 0, len(source.Groups)),
		UserGroups:    make([]Data.UserGroup, 0, len(source.UserGroups)),
		Media:         make([]Data.Media, 0, len(source.Media)),
		Templates:     make([]Data.Template, 0, len(source.Templates)),
		PostTemplates: make([]Data.PostTemplate, 0, len(source.PostTemplates)),
	}

	for _, row := range source.Domains {
		plan.Domains = append(plan.Domains, MapDomain(row))
	}
	for _, row := range source.Posts {
		plan.Posts = append(plan.Posts, MapPost(row))
	}
	for _, row := range source.URIs {
		plan.Redirects = append(plan.Redirects, MapRedirect(row))
		plan.URIMaps = append(plan.URIMaps, MapURIMap(row))
	}
	for _, row := range source.Users {
		user, warnings := MapUser(row)
		plan.Users = append(plan.Users, user)
		plan.Warnings = append(plan.Warnings, warnings...)
	}
	for _, row := range source.Groups {
		plan.Groups = append(plan.Groups, MapGroup(row))
	}
	userDomains := domainsByUserID(source.Users)
	groupDomains := domainsByGroupID(source.Groups)
	for _, row := range source.UserGroups {
		domain, warnings := derivedJoinDomain("user_group", row.UserID, row.GroupID, userDomains, groupDomains)
		plan.UserGroups = append(plan.UserGroups, MapUserGroup(row, domain))
		plan.Warnings = append(plan.Warnings, warnings...)
	}
	for _, row := range source.Media {
		media, warnings := MapMedia(row)
		plan.Media = append(plan.Media, media)
		plan.Warnings = append(plan.Warnings, warnings...)
	}
	for _, row := range source.Templates {
		plan.Templates = append(plan.Templates, MapTemplate(row))
	}
	postDomains := domainsByPostID(source.Posts)
	templateDomains := domainsByTemplateID(source.Templates)
	for _, row := range source.PostTemplates {
		domain, warnings := derivedJoinDomain("post_template", row.PostID, row.TemplateID, postDomains, templateDomains)
		plan.PostTemplates = append(plan.PostTemplates, MapPostTemplate(row, domain))
		plan.Warnings = append(plan.Warnings, warnings...)
	}

	return plan
}

func MapDomain(row V1Domain) Data.Domain {
	return Data.Domain{
		Id:              row.ID,
		Name:            row.Name,
		DNSZoneData:     row.DNSZoneData,
		CNAMESecret:     row.CNAMESecret,
		EmailSecretHash: row.EmailSecret,
		Status:          row.Status,
		Frozen:          row.Freezed != 0,
	}
}

func MapPost(row V1Post) Data.Post {
	return Data.Post{
		Id:         row.ID,
		OwnerId:    row.OwnerID,
		DeleterId:  row.DeleterID,
		RequestUri: row.RequestURI,
		Type:       row.Type,
		Date:       row.Date,
		Title:      row.Title,
		Body:       row.Text,
		Summary:    row.ShortText,
		ShortText:  row.ShortText,
		Tags:       row.Tags,
		Revision:   row.Version,
		Domain:     row.Domain,
		Status:     row.Status,
		Published:  legacyBool(row.Published),
	}
}

func MapRedirect(row V1URI) Data.Redirect {
	return Data.Redirect{
		Id:     row.ID,
		OldUri: row.OldURI,
		NewUri: row.NewURI,
		Date:   row.Date,
		Status: row.Status,
		Domain: row.Domain,
	}
}

func MapURIMap(row V1URI) Data.URIMap {
	return Data.URIMap{
		Id:     row.ID,
		OldUri: row.OldURI,
		NewUri: row.NewURI,
		Date:   row.Date,
		Status: row.Status,
		Domain: row.Domain,
	}
}

func MapUser(row V1User) (Data.User, []Warning) {
	user := Data.User{
		Id:                 row.ID,
		SessionId:          row.SessionID,
		OldId:              row.OldID,
		AvatarId:           row.AvatarID,
		Email:              row.Email,
		Nickname:           row.Nickname,
		FirstName:          row.FirstName,
		LastName:           row.LastName,
		Gender:             row.Gender,
		Phone:              row.Phone,
		DateOfRegistration: row.DateOfRegistration,
		DateOfBirth:        row.DateOfBirth,
		LastVisitTime:      row.LastVisitTime,
		GreenwichOffset:    row.GrinvichTimeOffset,
		Activated:          row.Activated,
		VerificationCode:   row.VerificationCode,
		Domain:             row.Domain,
		Status:             row.Status,
		Language:           row.Language,
		CurrentIP:          row.CurrentIP,
		Profile:            row.Profile,
		Preferences:        row.Preferences,
		SecurityLog:        row.SecurityLog,
		InvitedBy:          row.InvitedBy,
		InvitesAmount:      row.InvitesAmmount,
		QuotaBytes:         row.QuotaBytes,
		QuotaOriginals:     row.QuotaOriginals,
		QuotaBytesUsed:     row.QuotaBytesUsed,
		QuotaOriginalsUsed: row.QuotaOriginalsUsed,
		AutoGrab:           row.AutoGrab,
		DomainToGrab:       row.DomainToGrab,
	}

	if row.Password == "" {
		return user, nil
	}
	return user, []Warning{{
		Code:     WarningLegacyPassword,
		Entity:   "user",
		EntityID: row.ID,
		Field:    "password",
		Message:  "legacy v1 password material was not imported as an active password hash; force a password reset before login",
	}}
}

func MapGroup(row V1Group) Data.Group {
	return Data.Group{
		Id:      row.ID,
		OwnerId: row.OwnerID,
		Name:    row.Name,
		Title:   row.Title,
		Comment: row.Comment,
		Date:    row.Date,
		Status:  row.Status,
		Domain:  row.Domain,
	}
}

func MapUserGroup(row V1UserGroup, domain string) Data.UserGroup {
	return Data.UserGroup{
		UserId:  row.UserID,
		GroupId: row.GroupID,
		Status:  "active",
		Domain:  domain,
	}
}

func MapMedia(row V1Media) (Data.Media, []Warning) {
	width, widthWarnings := parseLegacyInt("media", row.ID, "width", row.Width)
	height, heightWarnings := parseLegacyInt("media", row.ID, "height", row.Height)
	warnings := append(widthWarnings, heightWarnings...)
	storagePath, pathWarnings := mediaStoragePath(row.ID, row.Hash, row.Format)
	warnings = append(warnings, pathWarnings...)

	return Data.Media{
		Id:           row.ID,
		Type:         row.Type,
		Hash:         row.Hash,
		OriginalHash: row.OriginalHash,
		Format:       row.Format,
		MimeType:     mediaMIMEType(row.Format),
		StoragePath:  storagePath,
		Width:        width,
		Height:       height,
		Status:       row.Status,
		Domain:       row.Domain,
		Day:          row.Day,
		Date:         row.Date,
		SizesArray:   row.SizesArray,
		Rating:       row.Rating,
		RatingCount:  row.RatingCount,
		RatingIP:     row.RatingIP,
		Views:        row.Views,
		BytesUsed:    row.BytesUsed,
	}, warnings
}

func MapTemplate(row V1Template) Data.Template {
	return Data.Template{
		Id:     row.ID,
		Name:   row.Name,
		Data:   row.Data,
		Status: row.Status,
		Domain: row.Domain,
	}
}

func MapPostTemplate(row V1PostTemplate, domain string) Data.PostTemplate {
	return Data.PostTemplate{
		PostId:     row.PostID,
		TemplateId: row.TemplateID,
		Status:     "active",
		Domain:     domain,
	}
}

func legacyBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "y", "on", "published", "public", "active":
		return true
	default:
		return false
	}
}

func isMD5Hash(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func parseLegacyInt(entity string, entityID int64, field string, value string) (int, []Warning) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err == nil && parsed >= 0 {
		return parsed, nil
	}
	return 0, []Warning{{
		Code:     WarningInvalidInteger,
		Entity:   entity,
		EntityID: entityID,
		Field:    field,
		Message:  fmt.Sprintf("legacy %s value %q could not be converted to an integer", field, value),
	}}
}

func mediaMIMEType(format string) string {
	switch strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), ".")) {
	case "jpg", "jpeg":
		return "image/jpeg"
	case "png":
		return "image/png"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	default:
		return ""
	}
}

func mediaStoragePath(entityID int64, hash string, format string) (string, []Warning) {
	hash = strings.TrimSpace(hash)
	format = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), "."))
	if hash == "" || format == "" {
		return "", nil
	}
	if !isMD5Hash(hash) {
		return "", []Warning{{
			Code:     WarningUnsafeMediaLocation,
			Entity:   "media",
			EntityID: entityID,
			Field:    "hash",
			Message:  "legacy media hash is not a 32-character hex digest; storage path was not derived",
		}}
	}
	if !isSafePublicMediaFormat(format) {
		return "", []Warning{{
			Code:     WarningUnsafeMediaLocation,
			Entity:   "media",
			EntityID: entityID,
			Field:    "format",
			Message:  "legacy media format is not in the safe import allowlist; storage path was not derived",
		}}
	}

	return "/f/" + hash + "." + format, nil
}

func isSafePublicMediaFormat(format string) bool {
	switch strings.ToLower(strings.TrimPrefix(strings.TrimSpace(format), ".")) {
	case "jpg", "jpeg", "png", "gif", "webp":
		return true
	default:
		return false
	}
}

func domainsByUserID(rows []V1User) map[int64]string {
	domains := make(map[int64]string, len(rows))
	for _, row := range rows {
		domains[row.ID] = row.Domain
	}
	return domains
}

func domainsByGroupID(rows []V1Group) map[int64]string {
	domains := make(map[int64]string, len(rows))
	for _, row := range rows {
		domains[row.ID] = row.Domain
	}
	return domains
}

func domainsByPostID(rows []V1Post) map[int64]string {
	domains := make(map[int64]string, len(rows))
	for _, row := range rows {
		domains[row.ID] = row.Domain
	}
	return domains
}

func domainsByTemplateID(rows []V1Template) map[int64]string {
	domains := make(map[int64]string, len(rows))
	for _, row := range rows {
		domains[row.ID] = row.Domain
	}
	return domains
}

func derivedJoinDomain(entity string, leftID int64, rightID int64, leftDomains map[int64]string, rightDomains map[int64]string) (string, []Warning) {
	leftDomain := strings.TrimSpace(leftDomains[leftID])
	rightDomain := strings.TrimSpace(rightDomains[rightID])

	if leftDomain != "" && rightDomain != "" {
		if leftDomain == rightDomain {
			return leftDomain, nil
		}
		return "", []Warning{{
			Code:     WarningDomainMismatch,
			Entity:   entity,
			EntityID: leftID,
			Field:    "domain",
			Message:  "v1 join references rows from different domains; join domain was not derived",
		}}
	}
	if leftDomain != "" {
		return leftDomain, nil
	}
	if rightDomain != "" {
		return rightDomain, nil
	}

	return "", []Warning{{
		Code:     WarningMissingDomain,
		Entity:   entity,
		EntityID: leftID,
		Field:    "domain",
		Message:  "v1 join table has no domain column and no related row domain could be derived",
	}}
}
