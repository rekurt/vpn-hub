package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Editor changes one field of one configuration file in place.
//
// It works on the YAML node tree rather than decoding and re-encoding, so comments,
// key order and formatting survive. That matters more here than it looks: for network
// configuration the comment explaining why a route exists is often worth more than
// the route, and a command that silently strips it makes the file less useful every
// time it runs.
type Editor struct {
	// Root is the configuration file or directory.
	Root string
}

// tunnelFiles returns the files that could hold a tunnel definition.
func (e Editor) tunnelFiles() ([]string, error) {
	if !IsDirectory(e.Root) {
		return []string{e.Root}, nil
	}
	paths, err := TunnelFiles(e.Root)
	if err != nil {
		return nil, err
	}
	// hub.yaml may hold tunnels in a single-file-style layout.
	return append(paths, filepath.Join(e.Root, hubFile)), nil
}

// deviceFiles returns the files that could hold a device definition.
func (e Editor) deviceFiles() []string {
	if !IsDirectory(e.Root) {
		return []string{e.Root}
	}
	return []string{filepath.Join(e.Root, devicesFile), filepath.Join(e.Root, hubFile)}
}

// SetTunnelField sets a scalar field on one tunnel, creating it if absent.
func (e Editor) SetTunnelField(tunnelID, field, value string) error {
	paths, err := e.tunnelFiles()
	if err != nil {
		return err
	}
	return e.setField(paths, "tunnels", tunnelID, field, value,
		fmt.Sprintf("no tunnel %q in %s", tunnelID, e.Root))
}

// SetDeviceField sets a scalar field on one device.
func (e Editor) SetDeviceField(deviceID, field, value string) error {
	return e.setField(e.deviceFiles(), "devices", deviceID, field, value,
		fmt.Sprintf("no device %q in %s", deviceID, e.Root))
}

func (e Editor) setField(paths []string, section, id, field, value, notFound string) error {
	for _, path := range paths {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		entry := findEntry(document, section, id)
		if entry == nil {
			continue
		}
		setScalar(entry, field, value)
		return writeDocument(path, document)
	}
	return fmt.Errorf("%s", notFound)
}

// AppendListItem adds a value to a sequence field, refusing duplicates.
func (e Editor) AppendListItem(tunnelID, field, value string) error {
	paths, err := e.tunnelFiles()
	if err != nil {
		return err
	}
	for _, path := range paths {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		entry := findEntry(document, "tunnels", tunnelID)
		if entry == nil {
			continue
		}
		list := findValue(entry, field)
		if list == nil {
			entry.Content = append(entry.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: field},
				&yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
			list = entry.Content[len(entry.Content)-1]
		}
		for _, item := range list.Content {
			if item.Value == value {
				return fmt.Errorf("%s already contains %q", field, value)
			}
		}
		list.Content = append(list.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
		return writeDocument(path, document)
	}
	return fmt.Errorf("no tunnel %q in %s", tunnelID, e.Root)
}

// RemoveListItem drops a value from a sequence field.
func (e Editor) RemoveListItem(tunnelID, field, value string) error {
	paths, err := e.tunnelFiles()
	if err != nil {
		return err
	}
	for _, path := range paths {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		entry := findEntry(document, "tunnels", tunnelID)
		if entry == nil {
			continue
		}
		list := findValue(entry, field)
		if list == nil {
			return fmt.Errorf("tunnel %q has no %s", tunnelID, field)
		}
		kept := list.Content[:0]
		found := false
		for _, item := range list.Content {
			if item.Value == value {
				found = true
				continue
			}
			kept = append(kept, item)
		}
		if !found {
			return fmt.Errorf("tunnel %q has no %s entry %q", tunnelID, field, value)
		}
		list.Content = kept
		return writeDocument(path, document)
	}
	return fmt.Errorf("no tunnel %q in %s", tunnelID, e.Root)
}

func readDocument(path string) (*yaml.Node, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &document, nil
}

func writeDocument(path string, document *yaml.Node) error {
	var builder strings.Builder
	encoder := yaml.NewEncoder(&builder)
	encoder.SetIndent(2)
	if err := encoder.Encode(document); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return os.WriteFile(path, []byte(builder.String()), 0o600)
}

// findEntry locates the mapping in section whose `id` matches.
func findEntry(document *yaml.Node, section, id string) *yaml.Node {
	if len(document.Content) == 0 {
		return nil
	}
	list := findValue(document.Content[0], section)
	if list == nil {
		return nil
	}
	for _, entry := range list.Content {
		if value := findValue(entry, "id"); value != nil && value.Value == id {
			return entry
		}
	}
	return nil
}

// findValue returns the value node for a key in a mapping.
func findValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func setScalar(mapping *yaml.Node, key, value string) {
	if existing := findValue(mapping, key); existing != nil {
		existing.Kind = yaml.ScalarNode
		existing.Tag = scalarTag(value)
		existing.Value = value
		existing.Style = 0
		return
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: scalarTag(value), Value: value})
}

func scalarTag(value string) string {
	if value == "true" || value == "false" {
		return "!!bool"
	}
	return "!!str"
}
