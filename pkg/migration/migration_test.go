package migration

import "testing"

func TestBuildImportPlanMapsCoreV1Entities(t *testing.T) {
	source := SourceData{
		Domains: []V1Domain{{
			ID:          7,
			Name:        "example.com",
			DNSZoneData: "example.com. 300 IN TXT sitebrush",
			CNAMESecret: "cname-secret",
			Status:      "active",
			EmailSecret: "email-secret-hash",
			Freezed:     1,
		}},
		Posts: []V1Post{{
			ID:         11,
			OwnerID:    3,
			DeleterID:  4,
			RequestURI: "/docs/page.html",
			Type:       "page",
			Date:       1700000001,
			Title:      "Legacy Page",
			Text:       "<p>Legacy body</p>",
			ShortText:  "Short body",
			Tags:       "alpha,beta",
			Version:    5,
			Domain:     "example.com",
			Status:     "active",
			Published:  "yes",
		}},
		URIs: []V1URI{{
			ID:     13,
			OldURI: "/old.html",
			NewURI: "/new.html",
			Date:   1700000002,
			Status: "active",
			Domain: "example.com",
		}},
		Users: []V1User{{
			ID:                 17,
			SessionID:          "legacy-session",
			OldID:              16,
			AvatarID:           19,
			Email:              "editor@example.com",
			Password:           "098f6bcd4621d373cade4e832627b4f6",
			Nickname:           "editor",
			FirstName:          "Ed",
			LastName:           "Itor",
			DateOfRegistration: 1700000003,
			LastVisitTime:      1700000004,
			Domain:             "example.com",
			Status:             "active",
			Language:           "en",
			AutoGrab:           "enabled",
			DomainToGrab:       "example.org",
		}},
		Groups: []V1Group{{
			ID:      23,
			OwnerID: 17,
			Name:    "Superuser",
			Title:   "Administrators",
			Comment: "site admins",
			Date:    1700000005,
			Status:  "active",
			Domain:  "example.com",
		}},
		UserGroups: []V1UserGroup{{
			UserID:  17,
			GroupID: 23,
		}},
		Media: []V1Media{{
			ID:           29,
			Type:         "image",
			Hash:         "900150983cd24fb0d6963f7d28e17f72",
			OriginalHash: "f561aaf6ef0bf14d4208bb46a4ccb3ad",
			Format:       "png",
			Width:        "640",
			Height:       "480",
			Status:       "active",
			Domain:       "example.com",
			Day:          20240102,
			Date:         1700000006,
			SizesArray:   `{"small":"abc123-small.png"}`,
			Rating:       4.5,
			RatingCount:  8,
			RatingIP:     "127.0.0.1",
			Views:        42,
			BytesUsed:    12345,
		}},
		Templates: []V1Template{{
			ID:     31,
			Name:   "hero",
			Data:   "<section>Hero</section>",
			Status: "active",
			Domain: "example.com",
		}},
		PostTemplates: []V1PostTemplate{{
			PostID:     11,
			TemplateID: 31,
		}},
	}

	plan := BuildImportPlan(source)

	if got := len(plan.Domains); got != 1 {
		t.Fatalf("Domains count = %d, want 1", got)
	}
	if domain := plan.Domains[0]; domain.Name != "example.com" || domain.DNSZoneData != "example.com. 300 IN TXT sitebrush" || domain.CNAMESecret != "cname-secret" || domain.EmailSecretHash != "email-secret-hash" || !domain.Frozen {
		t.Fatalf("domain not preserved: %+v", domain)
	}

	if got := len(plan.Posts); got != 1 {
		t.Fatalf("Posts count = %d, want 1", got)
	}
	post := plan.Posts[0]
	if post.RequestUri != "/docs/page.html" || post.Title != "Legacy Page" || post.Body != "<p>Legacy body</p>" || post.Tags != "alpha,beta" || post.Revision != 5 || post.Domain != "example.com" || post.Status != "active" || !post.Published {
		t.Fatalf("post not preserved: %+v", post)
	}

	if got := len(plan.Redirects); got != 1 {
		t.Fatalf("Redirects count = %d, want 1", got)
	}
	if redirect := plan.Redirects[0]; redirect.OldUri != "/old.html" || redirect.NewUri != "/new.html" || redirect.Domain != "example.com" {
		t.Fatalf("redirect not preserved: %+v", redirect)
	}
	if got := len(plan.URIMaps); got != 1 {
		t.Fatalf("URIMaps count = %d, want 1", got)
	}
	if uriMap := plan.URIMaps[0]; uriMap.OldUri != "/old.html" || uriMap.NewUri != "/new.html" || uriMap.Domain != "example.com" {
		t.Fatalf("uri map not preserved: %+v", uriMap)
	}

	if got := len(plan.Users); got != 1 {
		t.Fatalf("Users count = %d, want 1", got)
	}
	user := plan.Users[0]
	if user.Email != "editor@example.com" || user.Status != "active" || user.Domain != "example.com" || user.AutoGrab != "enabled" || user.DomainToGrab != "example.org" {
		t.Fatalf("user not preserved: %+v", user)
	}
	if user.PasswordHash != "" {
		t.Fatalf("legacy MD5 password imported as active hash: %q", user.PasswordHash)
	}
	assertWarning(t, plan.Warnings, WarningLegacyPassword, "user", 17, "password")

	if got := len(plan.Groups); got != 1 {
		t.Fatalf("Groups count = %d, want 1", got)
	}
	if group := plan.Groups[0]; group.Name != "Superuser" || group.Title != "Administrators" || group.Domain != "example.com" {
		t.Fatalf("group not preserved: %+v", group)
	}
	if got := len(plan.UserGroups); got != 1 {
		t.Fatalf("UserGroups count = %d, want 1", got)
	}
	if membership := plan.UserGroups[0]; membership.UserId != 17 || membership.GroupId != 23 || membership.Status != "active" || membership.Domain != "example.com" {
		t.Fatalf("user group not preserved: %+v", membership)
	}

	if got := len(plan.Media); got != 1 {
		t.Fatalf("Media count = %d, want 1", got)
	}
	media := plan.Media[0]
	if media.Hash != "900150983cd24fb0d6963f7d28e17f72" || media.OriginalHash != "f561aaf6ef0bf14d4208bb46a4ccb3ad" || media.Format != "png" || media.MimeType != "image/png" || media.StoragePath != "/f/900150983cd24fb0d6963f7d28e17f72.png" || media.Width != 640 || media.Height != 480 || media.SizesArray != `{"small":"abc123-small.png"}` || media.BytesUsed != 12345 {
		t.Fatalf("media not preserved: %+v", media)
	}

	if got := len(plan.Templates); got != 1 {
		t.Fatalf("Templates count = %d, want 1", got)
	}
	if template := plan.Templates[0]; template.Name != "hero" || template.Data != "<section>Hero</section>" || template.Domain != "example.com" {
		t.Fatalf("template not preserved: %+v", template)
	}
	if got := len(plan.PostTemplates); got != 1 {
		t.Fatalf("PostTemplates count = %d, want 1", got)
	}
	if link := plan.PostTemplates[0]; link.PostId != 11 || link.TemplateId != 31 || link.Status != "active" || link.Domain != "example.com" {
		t.Fatalf("post template not preserved: %+v", link)
	}
}

func TestMapUserNeverImportsLegacyPasswordAsActiveHash(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{name: "md5", password: "5f4dcc3b5aa765d61d8327deb882cf99"},
		{name: "unexpected legacy value", password: "$2a$12$abcdefghijklmnopqrstuvwxyz012345678901234567890123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, warnings := MapUser(V1User{
				ID:       2,
				Email:    "legacy@example.com",
				Password: tt.password,
			})
			if user.PasswordHash != "" {
				t.Fatalf("legacy password imported as active hash: %q", user.PasswordHash)
			}
			assertWarning(t, warnings, WarningLegacyPassword, "user", 2, "password")
		})
	}
}

func TestMapMediaWarnsForInvalidLegacyDimensions(t *testing.T) {
	media, warnings := MapMedia(V1Media{
		ID:     3,
		Hash:   "900150983cd24fb0d6963f7d28e17f72",
		Format: "jpg",
		Width:  "wide",
		Height: "200",
	})

	if media.Width != 0 || media.Height != 200 {
		t.Fatalf("media dimensions = %dx%d, want 0x200", media.Width, media.Height)
	}
	if media.MimeType != "image/jpeg" || media.StoragePath != "/f/900150983cd24fb0d6963f7d28e17f72.jpg" {
		t.Fatalf("media derived fields not set: %+v", media)
	}
	assertWarning(t, warnings, WarningInvalidInteger, "media", 3, "width")
}

func TestMapMediaRejectsUnsafeStoragePathInputs(t *testing.T) {
	tests := []struct {
		name   string
		hash   string
		format string
		field  string
	}{
		{name: "unsafe hash", hash: "../bad", format: "png", field: "hash"},
		{name: "unsafe format", hash: "900150983cd24fb0d6963f7d28e17f72", format: "../php", field: "format"},
		{name: "active svg format", hash: "900150983cd24fb0d6963f7d28e17f72", format: "svg", field: "format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			media, warnings := MapMedia(V1Media{
				ID:     4,
				Hash:   tt.hash,
				Format: tt.format,
			})
			if media.StoragePath != "" {
				t.Fatalf("unsafe storage path derived: %q", media.StoragePath)
			}
			assertWarning(t, warnings, WarningUnsafeMediaLocation, "media", 4, tt.field)
		})
	}
}

func TestBuildImportPlanDerivesJoinDomainsFromReferencedRows(t *testing.T) {
	plan := BuildImportPlan(SourceData{
		Posts: []V1Post{{
			ID:     10,
			Domain: "example.com",
		}},
		Templates: []V1Template{{
			ID:     11,
			Domain: "example.com",
		}},
		PostTemplates: []V1PostTemplate{{
			PostID:     10,
			TemplateID: 11,
		}},
		UserGroups: []V1UserGroup{{
			UserID:  98,
			GroupID: 99,
		}},
	})

	if got := plan.PostTemplates[0].Domain; got != "example.com" {
		t.Fatalf("post template domain = %q, want example.com", got)
	}
	assertWarning(t, plan.Warnings, WarningMissingDomain, "user_group", 98, "domain")
}

func TestBuildImportPlanWarnsOnJoinDomainMismatch(t *testing.T) {
	plan := BuildImportPlan(SourceData{
		Users: []V1User{{
			ID:     1,
			Domain: "example.com",
		}},
		Groups: []V1Group{{
			ID:     2,
			Domain: "other.example",
		}},
		UserGroups: []V1UserGroup{{
			UserID:  1,
			GroupID: 2,
		}},
	})

	if got := plan.UserGroups[0].Domain; got != "" {
		t.Fatalf("mismatched user group domain = %q, want empty", got)
	}
	assertWarning(t, plan.Warnings, WarningDomainMismatch, "user_group", 1, "domain")
}

func assertWarning(t *testing.T, warnings []Warning, code string, entity string, entityID int64, field string) {
	t.Helper()

	for _, warning := range warnings {
		if warning.Code == code && warning.Entity == entity && warning.EntityID == entityID && warning.Field == field {
			return
		}
	}
	t.Fatalf("warning %s/%s/%d/%s not found in %+v", code, entity, entityID, field, warnings)
}
