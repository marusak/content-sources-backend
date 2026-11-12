package config

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseEmailList parses a JSON array of email addresses. An empty string and
// "[]" are an empty list. Surrounding whitespace on each address is removed.
func ParseEmailList(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return []string{}, nil
	}
	var parsed []string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("parse email list: %w", err)
	}
	emails := make([]string, 0, len(parsed))
	for _, email := range parsed {
		email = strings.TrimSpace(email)
		if email != "" {
			emails = append(emails, email)
		}
	}
	return emails, nil
}
