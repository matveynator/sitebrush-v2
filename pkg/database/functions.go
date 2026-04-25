package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"sitebrush/pkg/config"
	"sitebrush/pkg/data"
)

func connectToDb(config Config.Settings) (db *sql.DB, err error) {
	if config.DB_TYPE == "genji" {
		db, err = sql.Open(config.DB_TYPE, config.DB_FULL_FILE_PATH)
		if err != nil {

			log.Println("Database error:", err)
			log.Println("Genji is unsupported on this architecture, switching to sqlite db type.")
			//переключаемся на sqlite для следующей попытки:
			config.DB_TYPE = "sqlite"
			db, err = sql.Open(config.DB_TYPE, config.DB_FULL_FILE_PATH)
			if err != nil {
				err = errors.New(fmt.Sprintf("Database file error: %s", err.Error()))
				log.Println(err)
				log.Println("SQLite is unsupported on this architecture, please use: -dbtype postgres.")
				return
			} else {
				err = createTables(db, config)
				if err != nil {
					err = errors.New(fmt.Sprintf("Database create tables error: %s", err.Error()))
					log.Println(err)
					return
				}
			}
		} else {
			err = createTables(db, config)
			if err != nil {
				err = errors.New(fmt.Sprintf("Database create tables error: %s", err.Error()))
				log.Println(err)
				return
			}
		}
	} else if config.DB_TYPE == "sqlite" {
		db, err = sql.Open(config.DB_TYPE, config.DB_FULL_FILE_PATH)
		if err != nil {
			log.Println("Database file error:", err)
			log.Println("SQLite is unsupported on this architecture, switching to genji db type.")
			config.DB_TYPE = "genji"
			db, err = sql.Open(config.DB_TYPE, config.DB_FULL_FILE_PATH)
			if err != nil {
				err = errors.New(fmt.Sprintf("Database file error: %s", err.Error()))
				log.Println(err)
				log.Println("Genji is unsupported on this architecture, please use: -dbtype postgres.")
				return
			} else {
				err = createTables(db, config)
				if err != nil {
					err = errors.New(fmt.Sprintf("Database create tables error: %s", err.Error()))
					log.Println(err)
					return
				}
			}
		} else {
			err = createTables(db, config)
			if err != nil {
				err = errors.New(fmt.Sprintf("Database create tables error: %s", err.Error()))
				log.Println(err)
				return
			}
		}
	} else if config.DB_TYPE == "postgres" {

		psqlConnectDSN := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s pool_max_conns=10", config.PG_HOST, config.PG_PORT, config.PG_USER, config.PG_PASS, config.PG_DB_NAME, config.PG_SSL)
		db, err = sql.Open("pgx", psqlConnectDSN)
		if err != nil {
			err = errors.New(fmt.Sprintf("Database config error: %s", err.Error()))
			log.Println(err)
			return
		}
		err = db.Ping()
		if err != nil {
			err = errors.New(fmt.Sprintf("Database connect error: %s", err.Error()))
			log.Println(err)
			return
		} else {
			err = createTables(db, config)
			if err != nil {
				err = errors.New(fmt.Sprintf("Database create tables error: %s", err.Error()))
				log.Println(err)
				return
			}
		}
	} else {
		err = errors.New("Please define valid dbtype (genji / sqlite)")
		log.Println(err)
		return
	}
	return
}

func createTables(db *sql.DB, config Config.Settings) (err error) {
	int64Type := int64ColumnType(config.DB_TYPE)
	primaryKeyType := primaryKeyColumnType(config.DB_TYPE)

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE if not exists DBWatchDog(
    Id %s,
    UnixTime %s
  )`, primaryKeyType, int64Type))

	if err != nil {
		return
	} else {
		//populate DBWatchDog with data (one row with only one Id=1)
		var id int64
		// Create a sql/database DB instance
		err = db.QueryRow("SELECT Id FROM DBWatchDog").Scan(&id)
		if err != nil {
			_, err = db.Exec(
				fmt.Sprintf("INSERT INTO DBWatchDog (Id,UnixTime) VALUES (%s)", sqlPlaceholders(config.DB_TYPE, 2)),
				1,
				time.Now().UnixMilli(),
			)
			if err != nil {
				return
			} else {
				log.Printf("Created new %s database file: %s \n", config.DB_TYPE, config.DB_FULL_FILE_PATH)
			}
		}
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS Post (
    Id %s,
    OwnerId INTEGER,
    EditorId INTEGER,
    DeleterId INTEGER,
    RequestUri TEXT,
    Type TEXT,
    Date %s,
    Title TEXT,
    Body TEXT,
    Header TEXT,
    Summary TEXT,
    ShortText TEXT,
    Tags TEXT,
    Revision INTEGER,
    Domain TEXT,
    Status TEXT,
    Published TEXT
  )`, primaryKeyType, int64Type))

	if err != nil {
		return
	}
	if err = ensurePostColumns(db, config.DB_TYPE); err != nil {
		return
	}

	if err = createFoundationTables(db, config.DB_TYPE); err != nil {
		return
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS SiteState (
    StateKey TEXT PRIMARY KEY,
    StateValue TEXT,
    UpdatedAt %s
  )`, int64Type))

	if err != nil {
		return
	}

	_, err = db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS Backup (
    Id %s,
    Domain TEXT,
    Path TEXT,
    Checksum TEXT,
    Size %s,
    Format TEXT,
    DownloadToken TEXT,
    CreatedAt %s,
    CompletedAt %s,
    Status TEXT,
    Error TEXT
  )`, primaryKeyType, int64Type, int64Type, int64Type))

	if err != nil {
		return
	}
	if err = ensureBackupColumns(db, config.DB_TYPE); err != nil {
		return
	}

	return
}

func createFoundationTables(db *sql.DB, dbType string) error {
	int64Type := int64ColumnType(dbType)
	boolType := boolColumnType(dbType)
	primaryKeyType := primaryKeyColumnType(dbType)

	statements := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS Domain (
			Id %s,
			Name TEXT,
			DNSZoneData TEXT,
			CNAMESecret TEXT,
			EmailSecretHash TEXT,
			Status TEXT,
			Frozen %s
		)`, primaryKeyType, boolType),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS UserAccount (
			Id %s,
			SessionId TEXT,
			OldId %s,
			AvatarId %s,
			Email TEXT,
			PasswordHash TEXT,
			Nickname TEXT,
			FirstName TEXT,
			LastName TEXT,
			Gender TEXT,
			Phone TEXT,
			DateOfRegistration %s,
			DateOfBirth %s,
			LastVisitTime %s,
			GreenwichOffset INTEGER,
			Activated TEXT,
			VerificationCode TEXT,
			Domain TEXT,
			Status TEXT,
			Language TEXT,
			CurrentIP TEXT,
			Profile TEXT,
			Preferences TEXT,
			SecurityLog TEXT,
			InvitedBy TEXT,
			InvitesAmount INTEGER,
			QuotaBytes TEXT,
			QuotaOriginals TEXT,
			QuotaBytesUsed %s,
			QuotaOriginalsUsed %s,
			AutoGrab TEXT,
			DomainToGrab TEXT
		)`, primaryKeyType, int64Type, int64Type, int64Type, int64Type, int64Type, int64Type, int64Type),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS GroupRole (
			Id %s,
			OwnerId %s,
			Name TEXT,
			Title TEXT,
			Comment TEXT,
			Date %s,
			Status TEXT,
			Domain TEXT
		)`, primaryKeyType, int64Type, int64Type),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS UserGroupRole (
			UserId %s,
			GroupId %s,
			Status TEXT,
			Domain TEXT
		)`, int64Type, int64Type),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS Redirect (
			Id %s,
			OldUri TEXT,
			NewUri TEXT,
			Date %s,
			Status TEXT,
			Domain TEXT
		)`, primaryKeyType, int64Type),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS Media (
			Id %s,
			Type TEXT,
			Hash TEXT,
			OriginalHash TEXT,
			Format TEXT,
			MimeType TEXT,
			StoragePath TEXT,
			Width INTEGER,
			Height INTEGER,
			Status TEXT,
			Domain TEXT,
			Day INTEGER,
			Date %s,
			SizesArray TEXT,
			Rating REAL,
			RatingCount INTEGER,
			RatingIP TEXT,
			Views INTEGER,
			BytesUsed %s
		)`, primaryKeyType, int64Type, int64Type),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS Template (
			Id %s,
			Name TEXT,
			Data TEXT,
			Status TEXT,
			Domain TEXT
		)`, primaryKeyType),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS PostTemplate (
			PostId %s,
			TemplateId %s,
			Status TEXT,
			Domain TEXT
		)`, int64Type, int64Type),
	}

	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

func int64ColumnType(dbType string) string {
	if dbType == "postgres" {
		return "BIGINT"
	}
	return "INTEGER"
}

func boolColumnType(dbType string) string {
	if dbType == "postgres" {
		return "BOOLEAN"
	}
	return "INTEGER"
}

func primaryKeyColumnType(dbType string) string {
	return int64ColumnType(dbType) + " PRIMARY KEY"
}

func sqlPlaceholder(dbType string, index int) string {
	if dbType == "postgres" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func sqlPlaceholders(dbType string, count int) string {
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = sqlPlaceholder(dbType, i+1)
	}
	return strings.Join(placeholders, ", ")
}

func ensurePostColumns(db *sql.DB, dbType string) error {
	if dbType == "genji" {
		return nil
	}

	columns := []struct {
		name       string
		definition string
	}{
		{"OwnerId", "INTEGER"},
		{"EditorId", "INTEGER"},
		{"DeleterId", "INTEGER"},
		{"RequestUri", "TEXT"},
		{"Type", "TEXT"},
		{"Date", int64ColumnType(dbType)},
		{"Title", "TEXT"},
		{"Body", "TEXT"},
		{"Header", "TEXT"},
		{"Summary", "TEXT"},
		{"ShortText", "TEXT"},
		{"Tags", "TEXT"},
		{"Revision", "INTEGER"},
		{"Domain", "TEXT"},
		{"Status", "TEXT"},
		{"Published", "TEXT"},
	}

	for _, column := range columns {
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE Post ADD COLUMN %s %s", column.name, column.definition)); err != nil && !isDuplicateColumnError(err) {
			return err
		}
	}
	return nil
}

func ensureBackupColumns(db *sql.DB, dbType string) error {
	if dbType == "genji" {
		return nil
	}

	columns := []struct {
		name       string
		definition string
	}{
		{"Domain", "TEXT"},
		{"Path", "TEXT"},
		{"Checksum", "TEXT"},
		{"Size", int64ColumnType(dbType)},
		{"Format", "TEXT"},
		{"DownloadToken", "TEXT"},
		{"CreatedAt", int64ColumnType(dbType)},
		{"CompletedAt", int64ColumnType(dbType)},
		{"Status", "TEXT"},
		{"Error", "TEXT"},
	}

	for _, column := range columns {
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE Backup ADD COLUMN %s %s", column.name, column.definition)); err != nil && !isDuplicateColumnError(err) {
			return err
		}
	}
	return nil
}

func isDuplicateColumnError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "duplicate column") ||
		(strings.Contains(message, "column") && strings.Contains(message, "already exists")) ||
		strings.Contains(message, "duplicate_column")
}

// SavePostDataInDB - функция для сохранения данных структуры Post в базу данных.
func SavePostDataInDB(databaseConnection *sql.DB, post Data.Post, dbTypes ...string) (err error) {
	dbType := "sqlite"
	if len(dbTypes) > 0 {
		dbType = dbTypes[0]
	}

	// Переменная для подсчета количества записей с указанным RequestUri.
	var count int

	// Пытаемся получить количество записей с таким же RequestUri, как у переданного post.
	err = databaseConnection.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM Post WHERE RequestUri = %s and Domain = %s", sqlPlaceholder(dbType, 1), sqlPlaceholder(dbType, 2)),
		post.RequestUri,
		post.Domain,
	).Scan(&count)

	// Если произошла ошибка при выполнении запроса, возвращаем ошибку.
	if err != nil {
		return err
	}
	//Подготавливаем номер ревизии:
	post.Revision = count + 1

	// Добавляем новую запись в таблицу Post с данными из структуры post.
	_, err = databaseConnection.Exec(
		fmt.Sprintf("INSERT INTO Post (Id, OwnerId, EditorId, DeleterId, RequestUri, Type, Date, Title, Body, Header, Summary, ShortText, Tags, Revision, Domain, Status, Published) VALUES (%s)", sqlPlaceholders(dbType, 17)),
		post.Id,
		post.OwnerId,
		post.EditorId,
		post.DeleterId,
		post.RequestUri,
		post.Type,
		post.Date,
		post.Title,
		post.Body,
		post.Header,
		post.Summary,
		post.ShortText,
		post.Tags,
		post.Revision,
		post.Domain,
		post.Status,
		post.Published,
	)

	// Если при добавлении записи произошла ошибка, возвращаем эту ошибку.
	if err != nil {
		return err
	}

	// Если функция успешно выполнена, возвращаем nil (нет ошибки).
	return nil
}
