package Config

import (
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"runtime"
	"time"
)

var CompileVersion string

type Settings struct {
	APP_NAME                   string
	VERSION                    string
	WEB_LISTENER_ADDRESS_HASH  string
	WEB_LISTENER_ADDRESS       string
	WEB_FILE_PATH              string
	WEB_INDEX_FILE             string
	LOCALHOST_LISTENER_ADDRESS string
	DB_TYPE                    string
	DB_FILE_PATH               string
	DB_FULL_FILE_PATH          string
	PG_HOST                    string
	PG_USER                    string
	PG_PASS                    string
	PG_DB_NAME                 string
	PG_SSL                     string
	TIME_ZONE                  string
	PG_PORT                    int
	WEB_PORT                   int
	DB_SAVE_INTERVAL_DURATION  time.Duration
	GUI                        bool
}

func hash(s string) string {
	hash := fnv.New32a()
	hash.Write([]byte(s))
	return fmt.Sprint(hash.Sum32())
}

func DBFullFilePath(appName, dbPath, listenerAddressHash, dbType string) string {
	return fmt.Sprintf("%s/%s.%s.db.%s", dbPath, appName, listenerAddressHash, dbType)
}

func ParseFlags() (config Settings) {
	config.APP_NAME = "sitebrush"
	flagVersion := flag.Bool("version", false, "Output version information")

	if runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		flag.BoolVar(&config.GUI, "gui", false, "Start application with graphic user interface (GUI).")
	} else {
		config.GUI = false
	}

	//web
	flag.IntVar(&config.WEB_PORT, "web-port", 2444, "Web server port on which HTTP web interface will be running.")
	flag.StringVar(&config.WEB_FILE_PATH, "web-path", "public_html", "Provide path to writable directory to store public_html website data.")
	flag.StringVar(&config.WEB_INDEX_FILE, "web-index-file", "index.html", "Provide web index file name.")

	flag.StringVar(&config.TIME_ZONE, "timezone", "UTC", "Set race timezone. Example: Europe/Paris, Africa/Dakar, UTC, https://en.wikipedia.org/wiki/List_of_tz_database_time_zones")

	//db
	flag.StringVar(&config.DB_FILE_PATH, "db-path", ".", "Provide path to writable directory to store database data.")
	flag.StringVar(&config.DB_TYPE, "db-type", "genji", "Select db type: sqlite / genji / postgres")
	flag.DurationVar(&config.DB_SAVE_INTERVAL_DURATION, "db-save-interval", 30000*time.Millisecond, "Duration to save data from memory to database (disk). Setting duration too low may cause unpredictable performance results.")

	//PostgreSQL related start
	flag.StringVar(&config.PG_HOST, "pg-host", "127.0.0.1", "PostgreSQL DB host.")
	flag.IntVar(&config.PG_PORT, "pg-port", 5432, "PostgreSQL DB port.")
	flag.StringVar(&config.PG_USER, "pg-user", "postgres", "PostgreSQL DB user.")
	flag.StringVar(&config.PG_PASS, "pg-pass", "", "PostgreSQL DB password.")
	flag.StringVar(&config.PG_DB_NAME, "pg-db-name", "chicha", "PostgreSQL DB name.")
	flag.StringVar(&config.PG_SSL, "pg-ssl", "prefer", "disable / allow / prefer / require / verify-ca / verify-full - PostgreSQL ssl modes: https://www.postgresql.org/docs/current/libpq-ssl.html")

	//process all flags
	flag.Parse()

	config.WEB_LISTENER_ADDRESS = fmt.Sprintf("0.0.0.0:%d", config.WEB_PORT)
	config.LOCALHOST_LISTENER_ADDRESS = fmt.Sprintf("127.0.0.1:%d", config.WEB_PORT)

	//делаем хеш от порта коллектора чтобы использовать в уникальном названии файла бд
	config.WEB_LISTENER_ADDRESS_HASH = hash(config.WEB_LISTENER_ADDRESS)

	//путь к файлу бд
	config.DB_FULL_FILE_PATH = DBFullFilePath(config.APP_NAME, config.DB_FILE_PATH, config.WEB_LISTENER_ADDRESS_HASH, config.DB_TYPE)

	//set version from CompileVersion variable at build time
	config.VERSION = CompileVersion

	if *flagVersion {
		if config.VERSION != "" {
			fmt.Println("Version:", config.VERSION)
		}
		os.Exit(0)
	}

	// Startup banner START:
	fmt.Printf("Starting %s ", config.APP_NAME)
	if config.VERSION != "" {
		fmt.Printf("version %s ", config.VERSION)
	}
	fmt.Printf("at %s", config.WEB_LISTENER_ADDRESS)
	fmt.Printf("\n")

	// END.

	return
}
