package parser

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"
)

// parseCSV streams rows and extracts packages from a packageurl column (header may be preceded by metadata rows).
func parseCSV(r io.Reader, tr *trace) ([]Package, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	purlCol := -1
	var packages []Package
	dataRows := 0
	loggedHeaderSearch := false

	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("could not read CSV: %w", err)
		}

		if purlCol < 0 {
			for i, field := range record {
				if strings.TrimSpace(strings.ToLower(field)) == "packageurl" {
					purlCol = i
					break
				}
			}
			if purlCol >= 0 {
				tr.note("Selecting column packageurl, ignoring all other columns")
			} else if !loggedHeaderSearch {
				tr.note("Looking for a packageurl column")
				loggedHeaderSearch = true
			}
			continue
		}

		dataRows++
		if purlCol >= len(record) {
			tr.skip("Entry %q is missing the packageurl column", "")
			continue
		}
		purl := strings.TrimSpace(record[purlCol])
		if purl == "" {
			tr.skip("Entry %q is empty", purl)
			continue
		}
		if pkg := parsePURL(purl); pkg != nil {
			packages = append(packages, *pkg)
		} else {
			tr.skip("Entry %q is not a valid purl", purl)
		}
	}

	if purlCol < 0 {
		return nil, errors.New("CSV is missing the required packageurl column")
	}
	tr.note("%d lines found", dataRows)
	return packages, nil
}
