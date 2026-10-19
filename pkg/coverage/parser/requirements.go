package parser

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// parseRequirements streams a pip requirements file; only ==/=== specifiers produce a pinned version.
func parseRequirements(r io.Reader, tr *trace) ([]Package, error) {
	var packages []Package
	var continuation strings.Builder
	scanner := bufio.NewScanner(r)
	lines := 0

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasSuffix(line, "\\") {
			continuation.WriteString(line[:len(line)-1])
			continue
		}
		if continuation.Len() > 0 {
			continuation.WriteString(line)
			line = continuation.String()
			continuation.Reset()
		}

		// Strip inline comments
		if before, _, found := strings.Cut(line, "#"); found {
			line = before
		}
		line = strings.TrimSpace(line)

		// Skip blank lines and pip flags (-r, -c, -e, --index-url, etc.).
		if line == "" || strings.HasPrefix(line, "-") {
			// Editable requirements represent package entries, unlike configuration flags.
			if strings.HasPrefix(line, "-e ") || strings.HasPrefix(line, "--editable ") || strings.HasPrefix(line, "--editable=") {
				lines++
				tr.skip("Entry %q is an editable requirement", line)
			}
			continue
		}
		lines++

		// Strip per-requirement options (e.g. --hash after continuation)
		if before, _, found := strings.Cut(line, " --"); found {
			line = strings.TrimSpace(before)
		}

		// Strip environment markers
		if before, _, found := strings.Cut(line, ";"); found {
			line = strings.TrimSpace(before)
		}

		// Handle direct URL references (PEP 508): name @ https://...
		if before, _, found := strings.Cut(line, " @ "); found {
			line = strings.TrimSpace(before)
		}

		// Strip extras: name[extra1,extra2]
		if before, after, found := strings.Cut(line, "["); found {
			_, rest, _ := strings.Cut(after, "]")
			line = before + rest
		}

		// Split name and version specifier
		var version string
		pkgName := line
		// Only == and === pin an exact version
		if idx := strings.IndexAny(line, "=~!><"); idx >= 0 {
			pkgName = line[:idx]
			op := line[idx:]
			rest := strings.TrimLeft(op, "=~!><")
			if strings.HasPrefix(op, "==") {
				version, _, _ = strings.Cut(strings.TrimSpace(rest), ",")
			}
		}
		pkgName = strings.TrimSpace(pkgName)

		if pkgName == "" {
			tr.skip("Entry %q has no package name", line)
			continue
		}

		packages = append(packages, Package{
			Ecosystem: EcosystemPython,
			Name:      pkgName,
			Version:   version,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if continuation.Len() > 0 {
		return nil, fmt.Errorf("unexpected end of file during line continuation")
	}
	tr.note("%d lines found", lines)
	return packages, nil
}
