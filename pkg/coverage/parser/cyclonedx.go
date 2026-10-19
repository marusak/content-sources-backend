package parser

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

type cdxComponent struct {
	Group      string         `xml:"group"`
	Name       string         `xml:"name"`
	Version    string         `xml:"version"`
	PURL       string         `xml:"purl"`
	Components []cdxComponent `xml:"components>component"`
}

// parseCycloneDX dispatches JSON or XML from the first non-space byte.
func parseCycloneDX(r *bufio.Reader, tr *trace) ([]Package, error) {
	start, err := peekSBOMStart(r)
	if err != nil {
		return nil, fmt.Errorf("reading CycloneDX SBOM: %w", err)
	}
	switch start {
	case '{', '[':
		tr.note("Content is JSON")
		return parseCycloneDXJSON(r, tr)
	case '<':
		tr.note("Content is XML")
		return parseCycloneDXXML(r, tr)
	default:
		return nil, fmt.Errorf("unsupported CycloneDX encoding (supported: JSON, XML); file starts with %q", string(start))
	}
}

// parseCycloneDXJSON streams metadata.component and components[] without loading the rest of the BOM.
func parseCycloneDXJSON(r io.Reader, tr *trace) ([]Package, error) {
	dec := json.NewDecoder(r)
	var pkgs []Package

	err := readJSONObject(dec, map[string]jsonFieldHandler{
		"metadata": func(d *json.Decoder) error {
			return readJSONObject(d, map[string]jsonFieldHandler{
				"component": func(d *json.Decoder) error {
					extracted, err := parseCDXJSONComponent(d, tr)
					pkgs = append(pkgs, extracted...)
					return err
				},
			})
		},
		"components": func(d *json.Decoder) error {
			return appendParsedJSONArray(d, &pkgs, func(d *json.Decoder) ([]Package, error) { return parseCDXJSONComponent(d, tr) })
		},
	})
	return pkgs, wrapParse("CycloneDX JSON", err)
}

// parseCDXJSONComponent streams one component and any nested components[] under it.
func parseCDXJSONComponent(dec *json.Decoder, tr *trace) ([]Package, error) {
	var purl, group, name, version string
	var pkgs []Package

	err := readJSONObject(dec, map[string]jsonFieldHandler{
		"purl":    func(d *json.Decoder) error { return decodeJSONString(d, &purl) },
		"group":   func(d *json.Decoder) error { return decodeJSONString(d, &group) },
		"name":    func(d *json.Decoder) error { return decodeJSONString(d, &name) },
		"version": func(d *json.Decoder) error { return decodeJSONString(d, &version) },
		"components": func(d *json.Decoder) error {
			return appendParsedJSONArray(d, &pkgs, func(d *json.Decoder) ([]Package, error) { return parseCDXJSONComponent(d, tr) })
		},
	})
	if err != nil {
		return nil, err
	}
	before := len(pkgs)
	pkgs = appendFromCDXIdentity(pkgs, purl, group, name, version)
	if len(pkgs) == before {
		tr.skip("%s", cdxSkipReason(purl, group, name))
	}
	return pkgs, nil
}

// parseCycloneDXXML walks component elements and skips tools/vulnerabilities so they are not treated as inventory.
func parseCycloneDXXML(r io.Reader, tr *trace) ([]Package, error) {
	var pkgs []Package
	err := forEachXMLStart(r, func(dec *xml.Decoder, se xml.StartElement) error {
		switch se.Name.Local {
		case "tools", "vulnerabilities", "dependencies", "services", "compositions",
			"formulation", "annotations", "declarations", "externalReferences":
			return dec.Skip()
		case "component":
			extracted, err := decodeCDXXMLComponent(dec, se, tr)
			pkgs = append(pkgs, extracted...)
			return err
		}
		return nil
	})
	return pkgs, wrapParse("CycloneDX XML", err)
}

// decodeCDXXMLComponent reads one <component> subtree, including nested children.
func decodeCDXXMLComponent(dec *xml.Decoder, start xml.StartElement, tr *trace) ([]Package, error) {
	var c cdxComponent
	if err := dec.DecodeElement(&c, &start); err != nil {
		return nil, err
	}
	return flattenCDXComponent(c, tr), nil
}

// flattenCDXComponent turns a component and its nested children into packages.
func flattenCDXComponent(c cdxComponent, tr *trace) []Package {
	pkgs := appendFromCDXIdentity(nil, c.PURL, c.Group, c.Name, c.Version)
	if len(pkgs) == 0 {
		tr.skip("%s", cdxSkipReason(c.PURL, c.Group, c.Name))
	}
	for _, child := range c.Components {
		pkgs = append(pkgs, flattenCDXComponent(child, tr)...)
	}
	return pkgs
}

func cdxSkipReason(purl, group, name string) string {
	purl = strings.TrimSpace(purl)
	if purl != "" {
		return fmt.Sprintf("Entry %q is not a valid purl", purl)
	}
	label := strings.Trim(strings.TrimSpace(group)+":"+strings.TrimSpace(name), ":")
	if label == "" {
		return `Entry "" could not be identified`
	}
	return fmt.Sprintf("Entry %q could not be identified", label)
}

// appendFromCDXIdentity prefers a purl, then treats CycloneDX group+name as Maven when no purl is present.
func appendFromCDXIdentity(pkgs []Package, purl, group, name, version string) []Package {
	pkgs = appendFromPURL(pkgs, purl)
	if parsePURL(strings.TrimSpace(purl)) != nil || group == "" || name == "" {
		return pkgs
	}
	constructed := "pkg:maven/" + group + "/" + name
	if version != "" {
		constructed += "@" + version
	}
	return appendFromPURL(pkgs, constructed)
}
