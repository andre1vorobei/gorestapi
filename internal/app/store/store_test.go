package store_test

import (
	"fmt"
	"os"
	"testing"
)

var (
	databaseURL string
)

func TestMain(m *testing.M) {
	databaseURL = os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		databaseURL = "user=testdb host=localhost password=1234 dbname=test"
	}

	fmt.Println(databaseURL)

	os.Exit(m.Run())

}
