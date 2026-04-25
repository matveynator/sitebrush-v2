package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	Config "sitebrush/pkg/config"
	Data "sitebrush/pkg/data"
)

// SaveMediaFromConfig opens the configured database, ensures the schema exists,
// and synchronously records uploaded media metadata.
func SaveMediaFromConfig(config Config.Settings, media Data.Media) (Data.Media, error) {
	dbConnection, err := connectToDb(config)
	if err != nil {
		return media, err
	}
	if dbConnection == nil {
		return media, errors.New("database connection is nil")
	}
	defer dbConnection.Close()

	return saveMediaInDB(dbConnection, media, config.DB_TYPE)
}

func saveMediaInDB(databaseConnection *sql.DB, media Data.Media, dbType string) (Data.Media, error) {
	if databaseConnection == nil {
		return media, errors.New("database connection is nil")
	}
	if media.Status == "" {
		media.Status = "active"
	}
	if media.Date == 0 {
		media.Date = time.Now().UnixMilli()
	}
	if media.Day == 0 {
		media.Day = dayFromUnixMillis(media.Date)
	}

	insertID := any(media.Id)
	var err error
	if media.Id == 0 {
		if dbType == "sqlite" {
			insertID = nil
		} else {
			media.Id, err = randomPostID()
			if err != nil {
				return media, err
			}
			insertID = media.Id
		}
	}

	result, err := databaseConnection.Exec(
		fmt.Sprintf(`INSERT INTO Media (Id, Type, Hash, OriginalHash, Format, MimeType, StoragePath, Width, Height, Status, Domain, Day, Date, SizesArray, Rating, RatingCount, RatingIP, Views, BytesUsed) VALUES (%s)`, sqlPlaceholders(dbType, 19)),
		insertID,
		media.Type,
		media.Hash,
		media.OriginalHash,
		media.Format,
		media.MimeType,
		media.StoragePath,
		media.Width,
		media.Height,
		media.Status,
		media.Domain,
		media.Day,
		media.Date,
		media.SizesArray,
		media.Rating,
		media.RatingCount,
		media.RatingIP,
		media.Views,
		media.BytesUsed,
	)
	if err != nil {
		return media, err
	}
	if media.Id == 0 && dbType == "sqlite" {
		media.Id, err = result.LastInsertId()
		if err != nil {
			return media, err
		}
	}
	return media, nil
}

func dayFromUnixMillis(unixMillis int64) int {
	return time.UnixMilli(unixMillis).UTC().YearDay()
}
