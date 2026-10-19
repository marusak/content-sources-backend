package parser

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectFormat_CaseInsensitive(t *testing.T) {
	format, err := detectFormat("REPORT.CSV", bufio.NewReader(strings.NewReader("")), nil)
	assert.NoError(t, err)
	assert.Equal(t, FormatCSV, format)
}

func TestDeduplicate(t *testing.T) {
	pkgs := []Package{
		{Ecosystem: "Java", Name: "spring-core", Version: "5.3.20", Namespace: "org.springframework"},
		{Ecosystem: "Java", Name: "spring-core", Version: "5.3.20", Namespace: "org.springframework"},
		{Ecosystem: "Python", Name: "flask", Version: "3.0.3"},
		{Ecosystem: "Python", Name: "flask", Version: "3.0.3"},
		{Ecosystem: "Java", Name: "spring-core", Version: "6.0.0", Namespace: "org.springframework"},
	}
	result := deduplicate(pkgs)
	assert.Len(t, result, 3)
}

func TestParse_CSV(t *testing.T) {
	data := "vulnerability_id,packageurl\nCVE-001,pkg:pypi/flask@3.0.3\n"
	result, err := Parse("report.csv", strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, FormatCSV, result.InputFormat)
	assert.Len(t, result.Packages, 1)
}

func TestParse_Requirements(t *testing.T) {
	data := "flask==2.3.0\nrequests==2.31.0\n"
	result, err := Parse("requirements.txt", strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, FormatRequirements, result.InputFormat)
	assert.Len(t, result.Packages, 2)
}

func TestParse_UnsupportedFormat(t *testing.T) {
	_, err := Parse("manifest", strings.NewReader("binary data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Parsing file manifest")
	assert.Contains(t, err.Error(), "Filename has no recognized suffix")
	assert.Contains(t, err.Error(), "Inspecting file contents")
	assert.Contains(t, err.Error(), "Could not determine the manifest format")
	var reason *ReasonError
	require.ErrorAs(t, err, &reason)
	assert.Equal(t, err.Error(), reason.Reason)
}

func TestParse_XMLFormatDetection(t *testing.T) {
	data := `<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>app</artifactId></project>`
	result, err := Parse("foo.xml", strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, FormatPOM, result.InputFormat)
	assert.Contains(t, result.Log, "Parsing file foo.xml")
	assert.Contains(t, result.Log, "Recognized .xml suffix")
	assert.Contains(t, result.Log, ".xml does not select a format on its own")
	assert.Contains(t, result.Log, "Content looks like XML")
	assert.Contains(t, result.Log, "No CycloneDX markers")
	assert.Contains(t, result.Log, "Content matches a Maven POM")
	assert.Contains(t, result.Log, "Parsing POM")
}

func TestParse_CSVIgnoredEntries(t *testing.T) {
	data := "name,packageurl,version\nkept,pkg:pypi/flask@3.0.3,3.0.3\nbad,foo-bar,1\nempty,,\nweird,foo:123,1\n"
	result, err := Parse("foo.csv", strings.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, 3, result.SkippedEntries)
	assert.Contains(t, result.Log, "Recognized .csv suffix")
	assert.Contains(t, result.Log, "Selecting column packageurl, ignoring all other columns")
	assert.Contains(t, result.Log, "4 lines found")
	assert.Contains(t, result.Log, `WARNING: Entry "foo-bar" is not a valid purl`)
	assert.Contains(t, result.Log, `WARNING: Entry "" is empty`)
	assert.Contains(t, result.Log, `WARNING: Entry "foo:123" is not a valid purl`)
	assert.Contains(t, result.Log, "1 package identified")
	assert.Equal(t, 3, result.Warnings)
}

func TestParse_ReasonCapsIgnoredEntries(t *testing.T) {
	var b strings.Builder
	b.WriteString("packageurl\n")
	for i := 0; i < FailureWarningLimit+2; i++ {
		fmt.Fprintf(&b, "not-a-purl-%d\n", i)
	}
	result, err := Parse("packages.csv", strings.NewReader(b.String()))
	require.NoError(t, err)
	assert.Contains(t, result.Reason, "... and 2 more ignored entries")
	assert.NotContains(t, result.Reason, fmt.Sprintf("not-a-purl-%d", FailureWarningLimit+1))
	assert.Contains(t, result.Log, fmt.Sprintf(`Entry "not-a-purl-%d" is not a valid purl`, FailureWarningLimit+1))
}
