//go:build !darwin || !cgo

package database

import (
	"database/sql"
	"errors"
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

func sqliteTableColumns(t *testing.T, db *sql.DB, table string) map[string]bool {
	t.Helper()

	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("inspect %s schema: %v", table, err)
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
			t.Fatalf("scan %s column: %v", table, err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s schema: %v", table, err)
	}

	return columns
}

func sqliteTableColumnTypes(t *testing.T, db *sql.DB, table string) map[string]string {
	t.Helper()

	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("inspect %s schema: %v", table, err)
	}
	defer rows.Close()

	columns := map[string]string{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("scan %s column: %v", table, err)
		}
		columns[name] = typ
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s schema: %v", table, err)
	}

	return columns
}

func assertSQLiteTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count); err != nil {
		t.Fatalf("query table %s: %v", table, err)
	}
	if count != 1 {
		t.Fatalf("table %s count = %d, want 1", table, count)
	}
}

func assertColumnsExist(t *testing.T, columns map[string]bool, names ...string) {
	t.Helper()

	for _, name := range names {
		if !columns[name] {
			t.Fatalf("schema missing column %q", name)
		}
	}
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

	columns := sqliteTableColumns(t, db, "Post")
	assertColumnsExist(t, columns, "Id", "OwnerId", "EditorId", "DeleterId", "RequestUri", "Type", "Date", "Title", "Body", "Header", "Summary", "ShortText", "Tags", "Revision", "Domain", "Status", "Published")

	for _, table := range []string{"SiteState", "Backup"} {
		t.Run(table, func(t *testing.T) {
			assertSQLiteTableExists(t, db, table)
		})
	}
}

func TestCreateTablesCreatesV1FoundationSchema(t *testing.T) {
	db := openTestSQLiteDB(t)

	tests := []struct {
		table   string
		columns []string
	}{
		{table: "Domain", columns: []string{"Id", "Name", "DNSZoneData", "CNAMESecret", "EmailSecretHash", "Status", "Frozen"}},
		{table: "UserAccount", columns: []string{"Id", "SessionId", "OldId", "AvatarId", "Email", "PasswordHash", "Nickname", "FirstName", "LastName", "Domain", "Status", "AutoGrab", "DomainToGrab"}},
		{table: "GroupRole", columns: []string{"Id", "OwnerId", "Name", "Title", "Comment", "Date", "Status", "Domain"}},
		{table: "UserGroupRole", columns: []string{"UserId", "GroupId", "Status", "Domain"}},
		{table: "Redirect", columns: []string{"Id", "OldUri", "NewUri", "Date", "Status", "Domain"}},
		{table: "Media", columns: []string{"Id", "Type", "Hash", "OriginalHash", "Format", "MimeType", "StoragePath", "Width", "Height", "Status", "Domain", "BytesUsed"}},
		{table: "Template", columns: []string{"Id", "Name", "Data", "Status", "Domain"}},
		{table: "PostTemplate", columns: []string{"PostId", "TemplateId", "Status", "Domain"}},
	}

	for _, tt := range tests {
		t.Run(tt.table, func(t *testing.T) {
			assertSQLiteTableExists(t, db, tt.table)
			assertColumnsExist(t, sqliteTableColumns(t, db, tt.table), tt.columns...)
		})
	}

	assertColumnsExist(t, sqliteTableColumns(t, db, "Backup"), "Id", "Domain", "Path", "Checksum", "Size", "Format", "DownloadToken", "CreatedAt", "CompletedAt", "Status", "Error")
}

func TestDialectColumnTypes(t *testing.T) {
	tests := []struct {
		dbType    string
		wantInt64 string
		wantBool  string
	}{
		{dbType: "sqlite", wantInt64: "INTEGER", wantBool: "INTEGER"},
		{dbType: "genji", wantInt64: "INTEGER", wantBool: "INTEGER"},
		{dbType: "postgres", wantInt64: "BIGINT", wantBool: "BOOLEAN"},
	}

	for _, tt := range tests {
		t.Run(tt.dbType, func(t *testing.T) {
			if got := int64ColumnType(tt.dbType); got != tt.wantInt64 {
				t.Fatalf("int64ColumnType(%q) = %q, want %q", tt.dbType, got, tt.wantInt64)
			}
			if got := boolColumnType(tt.dbType); got != tt.wantBool {
				t.Fatalf("boolColumnType(%q) = %q, want %q", tt.dbType, got, tt.wantBool)
			}
			if got := primaryKeyColumnType(tt.dbType); got != tt.wantInt64+" PRIMARY KEY" {
				t.Fatalf("primaryKeyColumnType(%q) = %q, want %q", tt.dbType, got, tt.wantInt64+" PRIMARY KEY")
			}
		})
	}
}

func TestDialectPlaceholders(t *testing.T) {
	tests := []struct {
		name             string
		dbType           string
		placeholderIndex int
		wantPlaceholder  string
		count            int
		wantList         string
	}{
		{name: "sqlite", dbType: "sqlite", placeholderIndex: 2, wantPlaceholder: "?", count: 3, wantList: "?, ?, ?"},
		{name: "genji", dbType: "genji", placeholderIndex: 2, wantPlaceholder: "?", count: 3, wantList: "?, ?, ?"},
		{name: "postgres", dbType: "postgres", placeholderIndex: 2, wantPlaceholder: "$2", count: 3, wantList: "$1, $2, $3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sqlPlaceholder(tt.dbType, tt.placeholderIndex); got != tt.wantPlaceholder {
				t.Fatalf("sqlPlaceholder(%q, %d) = %q, want %q", tt.dbType, tt.placeholderIndex, got, tt.wantPlaceholder)
			}
			if got := sqlPlaceholders(tt.dbType, tt.count); got != tt.wantList {
				t.Fatalf("sqlPlaceholders(%q, %d) = %q, want %q", tt.dbType, tt.count, got, tt.wantList)
			}
		})
	}
}

func TestCreateTablesUsesSQLiteSafeFoundationTypes(t *testing.T) {
	db := openTestSQLiteDB(t)

	domainTypes := sqliteTableColumnTypes(t, db, "Domain")
	if got := domainTypes["Frozen"]; got != "INTEGER" {
		t.Fatalf("Domain.Frozen type = %q, want INTEGER", got)
	}

	mediaTypes := sqliteTableColumnTypes(t, db, "Media")
	if got := mediaTypes["BytesUsed"]; got != "INTEGER" {
		t.Fatalf("Media.BytesUsed type = %q, want INTEGER", got)
	}

	backupTypes := sqliteTableColumnTypes(t, db, "Backup")
	if got := backupTypes["Size"]; got != "INTEGER" {
		t.Fatalf("Backup.Size type = %q, want INTEGER", got)
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

	columns := sqliteTableColumns(t, db, "Post")
	assertColumnsExist(t, columns, "OwnerId", "EditorId", "DeleterId", "Type", "Date", "Body", "Header", "Summary", "ShortText", "Tags", "Revision", "Domain", "Status", "Published")
}

func TestCreateTablesAddsMissingBackupColumns(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite in-memory db: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE Backup (
		Id INTEGER PRIMARY KEY,
		Path TEXT,
		Checksum TEXT,
		Size INTEGER,
		CreatedAt INTEGER,
		Status TEXT,
		Error TEXT
	)`); err != nil {
		t.Fatalf("create legacy Backup table: %v", err)
	}

	cfg := Config.Settings{DB_TYPE: "sqlite", DB_FULL_FILE_PATH: ":memory:"}
	if err := createTables(db, cfg); err != nil {
		t.Fatalf("create tables with legacy Backup schema: %v", err)
	}

	columns := sqliteTableColumns(t, db, "Backup")
	assertColumnsExist(t, columns, "Domain", "Format", "DownloadToken", "CompletedAt")
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

func TestEnsureBackupColumnsSkipsGenji(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite in-memory db: %v", err)
	}
	defer db.Close()

	if err := ensureBackupColumns(db, "genji"); err != nil {
		t.Fatalf("ensureBackupColumns() with genji db type returned error: %v", err)
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

func TestProcessDatabaseSavePostTaskProcessesReceivedTaskOnly(t *testing.T) {
	taskQueue := make(chan Data.Post, 3)
	taskQueue <- Data.Post{Id: 2, RequestUri: "/second/"}
	taskQueue <- Data.Post{Id: 3, RequestUri: "/third/"}
	var saved []int64

	err := processDatabaseSavePostTask(Data.Post{Id: 1, RequestUri: "/first/"}, taskQueue, func(post Data.Post) error {
		saved = append(saved, post.Id)
		return nil
	}, func() {})
	if err != nil {
		t.Fatalf("processDatabaseSavePostTask() returned error: %v", err)
	}

	if len(saved) != 1 || saved[0] != 1 {
		t.Fatalf("saved posts = %v, want [1]", saved)
	}

	for _, wantID := range []int64{2, 3} {
		select {
		case post := <-taskQueue:
			if post.Id != wantID {
				t.Fatalf("queued post Id = %d, want %d", post.Id, wantID)
			}
		default:
			t.Fatalf("missing queued post %d", wantID)
		}
	}

	select {
	default:
	case post := <-taskQueue:
		t.Fatalf("unexpected extra queued post: %+v", post)
	}
}

func TestProcessDatabaseSavePostTaskRequeuesReceivedTaskOnFatalError(t *testing.T) {
	taskQueue := make(chan Data.Post, 1)
	failedPost := Data.Post{Id: 42, RequestUri: "/failed/"}

	err := processDatabaseSavePostTask(failedPost, taskQueue, func(post Data.Post) error {
		return errors.New("driver connection failed")
	}, func() {})
	if err == nil {
		t.Fatal("processDatabaseSavePostTask() returned nil, want error")
	}

	select {
	case post := <-taskQueue:
		if post.Id != failedPost.Id {
			t.Fatalf("requeued post Id = %d, want %d", post.Id, failedPost.Id)
		}
	default:
		t.Fatal("failed post was not requeued")
	}
}
