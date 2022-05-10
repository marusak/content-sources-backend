package models

import (
	"log"
	"os"
	"testing"

	"github.com/content-services/content-sources-backend/pkg/db"
)

func TestMain(m *testing.M) {
	//open database connection
	var err = db.Connect()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// run tests
	exitCode := m.Run()

	// close database connection

	if err != nil {
		log.Fatalf("%v", err)
	}

	if err := db.Close(); err != nil {
		log.Fatalf("%v", err)
	}
	os.Exit(exitCode)
}
