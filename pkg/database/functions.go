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

	_, err = db.Exec(`CREATE TABLE if not exists DBWatchDog(
    Id INT PRIMARY KEY, 
    UnixTime INT
  )`)

	if err != nil {
		return
	} else {
		//populate DBWatchDog with data (one row with only one Id=1)
		var id int64
		// Create a sql/database DB instance
		err = db.QueryRow("SELECT Id FROM DBWatchDog").Scan(&id)
		if err != nil {
			_, err = db.Exec("INSERT INTO DBWatchDog (Id,UnixTime) VALUES (?,?)", 1, time.Now().UnixMilli())
			if err != nil {
				return
			} else {
				log.Printf("Created new %s database file: %s \n", config.DB_TYPE, config.DB_FULL_FILE_PATH)
			}
		}
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS Post (
    Id INTEGER PRIMARY KEY,
    OwnerId INTEGER,
    EditorId INTEGER,
    RequestUri TEXT,
    Date INTEGER,
    Title TEXT,
    Body TEXT,
    Header TEXT,
    Tags TEXT,
    Revision INTEGER,
    Domain TEXT,
    Status TEXT,
    Published TEXT
  )`)

	if err != nil {
		return
	}
	if err = ensurePostColumns(db, config.DB_TYPE); err != nil {
		return
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS SiteState (
    Key TEXT PRIMARY KEY,
    Value TEXT,
    UpdatedAt INTEGER
  )`)

	if err != nil {
		return
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS Backup (
    Id INTEGER PRIMARY KEY,
    Path TEXT,
    Checksum TEXT,
    Size INTEGER,
    CreatedAt INTEGER,
    Status TEXT,
    Error TEXT
  )`)

	if err != nil {
		return
	}

	return
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
		{"RequestUri", "TEXT"},
		{"Date", "INTEGER"},
		{"Title", "TEXT"},
		{"Body", "TEXT"},
		{"Header", "TEXT"},
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

func isDuplicateColumnError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "duplicate column") ||
		(strings.Contains(message, "column") && strings.Contains(message, "already exists")) ||
		strings.Contains(message, "duplicate_column")
}

// SavePostDataInDB - функция для сохранения данных структуры Post в базу данных.
func SavePostDataInDB(databaseConnection *sql.DB, post Data.Post) (err error) {

	// Переменная для подсчета количества записей с указанным RequestUri.
	var count int

	// Пытаемся получить количество записей с таким же RequestUri, как у переданного post.
	err = databaseConnection.QueryRow("SELECT COUNT(*) FROM Post WHERE RequestUri = ? and Domain = ?", post.RequestUri, post.Domain).Scan(&count)

	// Если произошла ошибка при выполнении запроса, возвращаем ошибку.
	if err != nil {
		return err
	}
	//Подготавливаем номер ревизии:
	post.Revision = count + 1

	// Добавляем новую запись в таблицу Post с данными из структуры post.
	_, err = databaseConnection.Exec("INSERT INTO Post (Id, OwnerId, EditorId, RequestUri, Date, Title, Body, Header, Tags, Revision, Domain, Status, Published) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", post.Id, post.OwnerId, post.EditorId, post.RequestUri, post.Date, post.Title, post.Body, post.Header, post.Tags, post.Revision, post.Domain, post.Status, post.Published)

	// Если при добавлении записи произошла ошибка, возвращаем эту ошибку.
	if err != nil {
		return err
	}

	// Если функция успешно выполнена, возвращаем nil (нет ошибки).
	return nil
}
