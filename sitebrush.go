//go:build !gui

package main

import (
	"sitebrush/pkg/config"
	"sitebrush/pkg/database"
	"sitebrush/pkg/mylog"
	"sitebrush/pkg/webserver"
	"time"
)

func main() {

	settings := Config.ParseFlags()

	go MyLog.ErrorLogWorker()
	go webserver.Run(settings)
	go database.Run(settings)

	for {
		time.Sleep(10 * time.Second)
	}

}
