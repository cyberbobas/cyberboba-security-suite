package config_test

import (
	"cyberboba/internal/config"
	"os"
	"testing"
)

func TestExample(t *testing.T) {
	b, err := os.ReadFile("../../packaging/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(b); err != nil {
		t.Fatal(err)
	}
}
