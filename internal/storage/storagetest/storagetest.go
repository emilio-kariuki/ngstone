package storagetest

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

const postgresTestEnv = "NGSTONE_TEST_POSTGRES_URL"

func PostgresSchemaDSN(t testing.TB) string {
	t.Helper()
	base := os.Getenv(postgresTestEnv)
	if base == "" {
		t.Skipf("%s is not set; skipping PostgreSQL storage test", postgresTestEnv)
	}
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("random schema suffix: %v", err)
	}
	schema := "ngstone_test_" + hex.EncodeToString(data)
	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
	})
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse %s: %v", postgresTestEnv, err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
