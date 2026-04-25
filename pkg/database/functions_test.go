//go:build !darwin || !cgo

package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	Config "sitebrush/pkg/config"
	Data "sitebrush/pkg/data"
)

func openTestSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite in-memory db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close sqlite in-memory db: %v", err)
		}
	})

	cfg := Config.Settings{DB_TYPE: "sqlite", DB_FULL_FILE_PATH: ":memory:"}
	if err := createTables(db, cfg); err != nil {
		t.Fatalf("create tables: %v", err)
	}

	return db
}

func TestCreateTablesCreatesWatchdogAndPostSchema(t *testing.T) {
	db := openTestSQLiteDB(t)

	var watchdogRows int
	if err := db.QueryRow("SELECT COUNT(*) FROM DBWatchDog WHERE Id = ?", 1).Scan(&watchdogRows); err != nil {
		t.Fatalf("query watchdog seed row: %v", err)
	}
	if watchdogRows != 1 {
		t.Fatalf("watchdog rows for Id=1 = %d, want 1", watchdogRows)
	}

	rows, err := db.Query("PRAGMA table_info(Post)")
	if err != nil {
		t.Fatalf("inspect Post schema: %v", err)
	}
	defer rows.Close()

	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan Post column: %v", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate Post schema: %v", err)
	}

	for _, name := range []string{"Id", "OwnerId", "EditorId", "RequestUri", "Date", "Title", "Body", "Header", "Tags", "Revision", "Domain", "Status", "Published"} {
		if !columns[name] {
			t.Fatalf("Post schema missing column %q", name)
		}
	}

	for _, table := range []string{"SiteState", "Backup"} {
		t.Run(table, func(t *testing.T) {
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count); err != nil {
				t.Fatalf("query table %s: %v", table, err)
			}
			if count != 1 {
				t.Fatalf("table %s count = %d, want 1", table, count)
			}
		})
	}
}

func TestCreateTablesAddsMissingPostColumns(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite in-memory db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE Post (
		Id INTEGER PRIMARY KEY,
		RequestUri TEXT,
		Title TEXT
	)`); err != nil {
		t.Fatalf("create legacy Post table: %v", err)
	}

	cfg := Config.Settings{DB_TYPE: "sqlite", DB_FULL_FILE_PATH: ":memory:"}
	if err := createTables(db, cfg); err != nil {
		t.Fatalf("create tables with legacy Post schema: %v", err)
	}

	rows, err := db.Query("PRAGMA table_info(Post)")
	if err != nil {
		t.Fatalf("inspect migrated Post schema: %v", err)
	}
	defer rows.Close()

	columns := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan Post column: %v", err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migrated Post schema: %v", err)
	}

	for _, name := range []string{"OwnerId", "EditorId", "Date", "Body", "Header", "Tags", "Revision", "Domain", "Status", "Published"} {
		if !columns[name] {
			t.Fatalf("migrated Post schema missing column %q", name)
		}
	}
}

func TestEnsurePostColumnsSkipsGenji(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite in-memory db: %v", err)
	}
	defer db.Close()

	if err := ensurePostColumns(db, "genji"); err != nil {
		t.Fatalf("ensurePostColumns() with genji db type returned error: %v", err)
	}
}

func TestCreateTablesSupportsGenjiSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sitebrush-genji.db")
	db, err := sql.Open("genji", dbPath)
	if err != nil {
		t.Fatalf("open genji db: %v", err)
	}
	defer db.Close()

	cfg := Config.Settings{DB_TYPE: "genji", DB_FULL_FILE_PATH: dbPath}
	if err := createTables(db, cfg); err != nil {
		t.Fatalf("create tables with genji schema: %v", err)
	}
}

func TestSavePostDataInDBAssignsSequentialRevisionsPerDomainAndURI(t *testing.T) {
	db := openTestSQLiteDB(t)

	posts := []Data.Post{
		{Id: 1, RequestUri: "/about/", Domain: "example.test", Title: "first", Body: "v1", Published: true},
		{Id: 2, RequestUri: "/about/", Domain: "example.test", Title: "second", Body: "v2", Published: true},
		{Id: 3, RequestUri: "/about/", Domain: "other.test", Title: "other domain", Body: "v1", Published: false},
		{Id: 4, RequestUri: "/contact/", Domain: "example.test", Title: "other uri", Body: "v1", Published: false},
	}

	for _, post := range posts {
		if err := SavePostDataInDB(db, post); err != nil {
			t.Fatalf("SavePostDataInDB(%+v): %v", post, err)
		}
	}

	tests := []struct {
		name       string
		domain     string
		requestURI string
		want       []int
	}{
		{name: "same domain and uri increments", domain: "example.test", requestURI: "/about/", want: []int{1, 2}},
		{name: "different domain starts at one", domain: "other.test", requestURI: "/about/", want: []int{1}},
		{name: "different uri starts at one", domain: "example.test", requestURI: "/contact/", want: []int{1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows, err := db.Query("SELECT Revision FROM Post WHERE Domain = ? AND RequestUri = ? ORDER BY Revision", tt.domain, tt.requestURI)
			if err != nil {
				t.Fatalf("query revisions: %v", err)
			}
			defer rows.Close()

			var got []int
			for rows.Next() {
				var revision int
				if err := rows.Scan(&revision); err != nil {
					t.Fatalf("scan revision: %v", err)
				}
				got = append(got, revision)
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("iterate revisions: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("revisions = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("revisions = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
