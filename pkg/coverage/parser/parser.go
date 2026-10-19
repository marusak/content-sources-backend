package parser

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"strings"
)

const (
	EcosystemJava       = "Java"
	EcosystemPython     = "Python"
	EcosystemJavaScript = "JavaScript"
	EcosystemCSharp     = "C#"
	EcosystemGo         = "Go"
	EcosystemRust       = "Rust"
)

const (
	FormatCSV          = "csv"
	FormatRequirements = "requirements.txt"
	FormatPOM          = "pom.xml"
	FormatCycloneDX    = "CycloneDX"
	FormatSPDX         = "SPDX"
)

type Package struct {
	Ecosystem string
	Name      string
	Version   string
	Namespace string
}

type ParseResult struct {
	Packages    []Package
	InputFormat string
	// SkippedEntries counts package entries (CSV rows, logical requirement lines,
	// SBOM components, or POM dependencies) that yield no usable identity.
	// Headers, comments, configuration, and valid duplicates are excluded.
	SkippedEntries int
	// Log is the full parser trace, including every ignored entry.
	Log string
	// Reason is Log with ignored-entry warnings capped for display.
	Reason string
	// Warnings counts ignored-entry lines recorded in Log.
	Warnings int
}

// Parse detects the format of the manifest file and extracts package metadata.
func Parse(filename string, r io.Reader) (*ParseResult, error) {
	log := &Log{}
	tr := &trace{log: log}
	br := bufio.NewReader(r)
	discardUTF8BOM(br)

	format, err := detectFormat(filename, br, log)
	if err != nil {
		return nil, log.fail(err)
	}

	log.Printf("Parsing %s", formatLabel(format))

	var packages []Package
	switch format {
	case FormatCSV:
		packages, err = parseCSV(br, tr)
	case FormatRequirements:
		packages, err = parseRequirements(br, tr)
	case FormatPOM:
		packages, err = parsePOMs(br, tr)
	case FormatCycloneDX:
		packages, err = parseCycloneDX(br, tr)
	case FormatSPDX:
		packages, err = parseSPDX(br, tr)
	default:
		err = fmt.Errorf("unsupported manifest format for file %q", filename)
	}
	if err != nil {
		tr.flush()
		return nil, log.fail(err)
	}

	tr.flush()
	unique := deduplicate(packages)
	if removed := len(packages) - len(unique); removed > 0 {
		tr.note("Ignored %s", counted(removed, "duplicate package", "duplicate packages"))
	}
	tr.note("%s identified", counted(len(unique), "package", "packages"))
	if tr.skipped > 0 {
		tr.note("%s ignored", counted(tr.skipped, "entry", "entries"))
	}

	return &ParseResult{
		Packages:       unique,
		InputFormat:    format,
		SkippedEntries: tr.skipped,
		Log:            log.String(),
		Reason:         log.Reason(),
		Warnings:       log.WarningCount(),
	}, nil
}

func counted(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func formatLabel(format string) string {
	switch format {
	case FormatCSV:
		return "CSV"
	case FormatRequirements:
		return "requirements.txt"
	case FormatPOM:
		return "POM"
	default:
		return format
	}
}

// detectFormat uses the filename when it is unambiguous, otherwise peeks at the stream to sniff its format.
func detectFormat(filename string, r *bufio.Reader, log *Log) (string, error) {
	if log == nil {
		log = &Log{}
	}
	log.Printf("Parsing file %s", filename)
	lower := strings.ToLower(filename)
	base := path.Base(lower)
	switch {
	case strings.HasSuffix(lower, ".csv"):
		log.Printf("Recognized .csv suffix")
		return FormatCSV, nil
	case strings.HasSuffix(lower, "requirements.txt"):
		log.Printf("Recognized requirements.txt filename")
		return FormatRequirements, nil
	case base == "pom.xml" || hasAnySuffix(lower, ".pom", "pom.xml"):
		if strings.HasSuffix(lower, ".pom") && !strings.HasSuffix(lower, "pom.xml") {
			log.Printf("Recognized .pom suffix")
		} else {
			log.Printf("Recognized pom.xml filename")
		}
		return FormatPOM, nil
	case hasAnySuffix(lower, ".cdx.json", ".cdx.xml"):
		log.Printf("Recognized CycloneDX suffix")
		return FormatCycloneDX, nil
	case base == "bom.json" || base == "bom.xml":
		log.Printf("Recognized CycloneDX filename %s", base)
		return FormatCycloneDX, nil
	case hasAnySuffix(lower, ".spdx.json", ".spdx.tag", ".spdx"):
		log.Printf("Recognized SPDX suffix")
		return FormatSPDX, nil
	}

	ext := path.Ext(lower)
	if ext == "" {
		log.Printf("Filename has no recognized suffix")
	} else {
		log.Printf("Recognized %s suffix", ext)
		log.Printf("%s does not select a format on its own", ext)
	}
	log.Printf("Inspecting file contents")

	sniffed, err := sniffFormat(r, log)
	if err != nil {
		return "", err
	}
	if sniffed != "" {
		log.Printf("Selected %s from file contents", formatLabel(sniffed))
		return sniffed, nil
	}

	log.Printf("Could not determine the manifest format")
	log.Printf("Supported formats: CSV (.csv with a packageurl column), requirements.txt, Maven POM (pom.xml or .pom), CycloneDX (bom.json, bom.xml, .cdx.json, .cdx.xml, or JSON/XML with CycloneDX markers), SPDX (.spdx, .spdx.json, .spdx.tag, or content with SPDX markers)")
	//nolint:staticcheck // ST1005: this text is copied into the parser log shown to the user
	return "", fmt.Errorf("Could not determine the manifest format")
}

// deduplicate keeps the first occurrence of each ecosystem/namespace/name/version tuple.
func deduplicate(pkgs []Package) []Package {
	seen := make(map[string]struct{}, len(pkgs))
	result := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		key := p.Ecosystem + "|" + p.Namespace + "|" + p.Name + "|" + p.Version
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, p)
	}
	return result
}
