package database

import (
	"database/sql"
	"errors"
	"fmt"

	Config "sitebrush/pkg/config"
	Data "sitebrush/pkg/data"
)

// SaveTemplateFromConfig opens the configured database, ensures the schema
// exists, and stores detected template metadata for v1-compatible propagation
// foundations.
func SaveTemplateFromConfig(config Config.Settings, template Data.Template) (Data.Template, error) {
	dbConnection, err := connectToDb(config)
	if err != nil {
		return template, err
	}
	if dbConnection == nil {
		return template, errors.New("database connection is nil")
	}
	defer dbConnection.Close()

	return saveTemplateInDB(dbConnection, template, config.DB_TYPE)
}

func saveTemplateInDB(databaseConnection *sql.DB, template Data.Template, dbType string) (Data.Template, error) {
	if databaseConnection == nil {
		return template, errors.New("database connection is nil")
	}
	if template.Status == "" {
		template.Status = "active"
	}

	insertID := any(template.Id)
	var err error
	if template.Id == 0 {
		if dbType == "sqlite" {
			insertID = nil
		} else {
			template.Id, err = randomPostID()
			if err != nil {
				return template, err
			}
			insertID = template.Id
		}
	}

	result, err := databaseConnection.Exec(
		fmt.Sprintf("INSERT INTO Template (Id, Name, Data, Status, Domain) VALUES (%s)", sqlPlaceholders(dbType, 5)),
		insertID,
		template.Name,
		template.Data,
		template.Status,
		template.Domain,
	)
	if err != nil {
		return template, err
	}
	if template.Id == 0 && dbType == "sqlite" {
		template.Id, err = result.LastInsertId()
		if err != nil {
			return template, err
		}
	}
	return template, nil
}
