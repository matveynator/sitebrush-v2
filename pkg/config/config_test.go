package Config

import "testing"

func TestDBFullFilePath(t *testing.T) {
	got := DBFullFilePath("sitebrush", "data", "12345", "genji")
	want := "data/sitebrush.12345.db.genji"

	if got != want {
		t.Fatalf("DBFullFilePath() = %q, want %q", got, want)
	}
}

func TestHashIsStable(t *testing.T) {
	got := hash("0.0.0.0:2444")
	want := "274261711"

	if got != want {
		t.Fatalf("hash() = %q, want %q", got, want)
	}
}
