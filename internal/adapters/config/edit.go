package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	runtimeadapter "vpn-hub/internal/adapters/runtime"
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

// lock serializes whole read-modify-write cycles across processes. The editor is
// used by hubctl over SSH and by the bot at once; without this, two edits are
// last-writer-wins and one of them silently disappears.
func (e Editor) lock() (func(), error) {
	dir := e.Root
	if !IsDirectory(dir) {
		dir = filepath.Dir(dir)
	}
	return runtimeadapter.LockDir(dir)
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
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
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

// hubFiles returns the files that could hold the hub section.
func (e Editor) hubFiles() []string {
	if !IsDirectory(e.Root) {
		return []string{e.Root}
	}
	return []string{filepath.Join(e.Root, hubFile)}
}

// SetHubField sets a scalar field on the hub section.
func (e Editor) SetHubField(field, value string) error {
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
	for _, path := range e.hubFiles() {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		hub := documentMap(document, "hub")
		if hub == nil {
			continue
		}
		setScalar(hub, field, value)
		return writeDocument(path, document)
	}
	return fmt.Errorf("no hub section in %s", e.Root)
}

// SetHubMapField sets one key of a nested hub mapping (awg_interface in practice),
// creating the mapping when absent.
func (e Editor) SetHubMapField(mapName, key, value string) error {
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
	for _, path := range e.hubFiles() {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		hub := documentMap(document, "hub")
		if hub == nil {
			continue
		}
		setScalar(findOrCreateMap(hub, mapName), key, value)
		return writeDocument(path, document)
	}
	return fmt.Errorf("no hub section in %s", e.Root)
}

// RemoveHubMapField drops one key of a nested hub mapping.
func (e Editor) RemoveHubMapField(mapName, key string) error {
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
	for _, path := range e.hubFiles() {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		hub := documentMap(document, "hub")
		if hub == nil {
			continue
		}
		nested := findValue(hub, mapName)
		if nested == nil || !removeMapKey(nested, key) {
			return fmt.Errorf("hub %s has no %q", mapName, key)
		}
		return writeDocument(path, document)
	}
	return fmt.Errorf("no hub section in %s", e.Root)
}

// SetTunnelMapField sets one key of a tunnel's nested mapping (health in practice),
// creating the mapping when absent.
func (e Editor) SetTunnelMapField(tunnelID, mapName, key, value string) error {
	paths, err := e.tunnelFiles()
	if err != nil {
		return err
	}
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
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
		setScalar(findOrCreateMap(entry, mapName), key, value)
		return writeDocument(path, document)
	}
	return fmt.Errorf("no tunnel %q in %s", tunnelID, e.Root)
}

// RemoveTunnelMapField drops one key of a tunnel's nested mapping.
func (e Editor) RemoveTunnelMapField(tunnelID, mapName, key string) error {
	paths, err := e.tunnelFiles()
	if err != nil {
		return err
	}
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
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
		nested := findValue(entry, mapName)
		if nested == nil || !removeMapKey(nested, key) {
			return fmt.Errorf("tunnel %q %s has no %q", tunnelID, mapName, key)
		}
		return writeDocument(path, document)
	}
	return fmt.Errorf("no tunnel %q in %s", tunnelID, e.Root)
}

func (e Editor) clientACLFiles() []string {
	if !IsDirectory(e.Root) {
		return []string{e.Root}
	}
	return []string{filepath.Join(e.Root, hubFile)}
}

func (e Editor) AddClientACL(source, target, protocol string, port uint16) error {
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
	entry := clientACLNode(source, target, protocol, port)
	for _, path := range e.clientACLFiles() {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if duplicateClientACL(document, source, target, protocol, port) {
			return fmt.Errorf("client ACL %s -> %s %s/%d already exists", source, target, protocol, port)
		}
		root := document.Content[0]
		list := findValue(root, "client_acls")
		if list == nil {
			root.Content = append(root.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "client_acls"},
				&yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"})
			list = root.Content[len(root.Content)-1]
		}
		if list.Kind != yaml.SequenceNode {
			*list = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		}
		if len(list.Content) == 0 {
			list.Style = 0
		}
		list.Content = append(list.Content, entry)
		return writeDocument(path, document)
	}
	return fmt.Errorf("no config file in %s", e.Root)
}

func (e Editor) RemoveClientACL(source, target, protocol string, port uint16) error {
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
	for _, path := range e.clientACLFiles() {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		list := documentList(document, "client_acls")
		if list == nil {
			continue
		}
		for index, entry := range list.Content {
			if clientACLMatches(entry, source, target, protocol, port) {
				list.Content = append(list.Content[:index], list.Content[index+1:]...)
				return writeDocument(path, document)
			}
		}
	}
	return fmt.Errorf("no client ACL %s -> %s %s/%d in %s", source, target, protocol, port, e.Root)
}

func clientACLNode(source, target, protocol string, port uint16) *yaml.Node {
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, pair := range [][2]string{{"source", source}, {"target", target}, {"protocol", protocol}} {
		entry.Content = append(entry.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pair[0]},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pair[1]})
	}
	entry.Content = append(entry.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "port"},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(port)})
	return entry
}

func duplicateClientACL(document *yaml.Node, source, target, protocol string, port uint16) bool {
	list := documentList(document, "client_acls")
	if list == nil {
		return false
	}
	for _, entry := range list.Content {
		if clientACLMatches(entry, source, target, protocol, port) {
			return true
		}
	}
	return false
}

func clientACLMatches(entry *yaml.Node, source, target, protocol string, port uint16) bool {
	return scalarValue(entry, "source") == source &&
		scalarValue(entry, "target") == target &&
		scalarValue(entry, "protocol") == protocol &&
		scalarValue(entry, "port") == fmt.Sprint(port)
}

func scalarValue(mapping *yaml.Node, key string) string {
	if value := findValue(mapping, key); value != nil {
		return value.Value
	}
	return ""
}

// documentMap returns a top-level mapping by key, nil when absent.
func documentMap(document *yaml.Node, section string) *yaml.Node {
	if len(document.Content) == 0 {
		return nil
	}
	value := findValue(document.Content[0], section)
	if value == nil || value.Kind != yaml.MappingNode {
		return nil
	}
	return value
}

// findOrCreateMap returns the nested mapping under key, creating an empty one when
// it is absent -- `awg_interface` and `health` legitimately start nonexistent.
func findOrCreateMap(parent *yaml.Node, key string) *yaml.Node {
	if existing := findValue(parent, key); existing != nil {
		if existing.Kind != yaml.MappingNode {
			*existing = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		if len(existing.Content) == 0 {
			existing.Style = 0
		}
		return existing
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"})
	return parent.Content[len(parent.Content)-1]
}

// removeMapKey drops a key/value pair from a mapping, reporting whether it existed.
func removeMapKey(mapping *yaml.Node, key string) bool {
	if mapping.Kind != yaml.MappingNode {
		return false
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			mapping.Content = append(mapping.Content[:index], mapping.Content[index+2:]...)
			return true
		}
	}
	return false
}

// AppendListItem adds a value to a sequence field, refusing duplicates.
func (e Editor) AppendListItem(tunnelID, field, value string) error {
	paths, err := e.tunnelFiles()
	if err != nil {
		return err
	}
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
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
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
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

// AddDevice appends a device entry, creating the devices list if absent.
//
// The duplicate check runs across every file that could hold devices before
// anything is written: validation would also catch a duplicate, but the caller's
// revert is RemoveDevice, and removing "the device with this id" after appending a
// duplicate would take out the original.
func (e Editor) AddDevice(id, address, publicKey, egress string) error {
	paths := e.deviceFiles()
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
	for _, path := range paths {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if findEntry(document, "devices", id) != nil {
			return fmt.Errorf("device %q already exists in %s", id, path)
		}
	}

	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, pair := range [][2]string{
		{"id", id}, {"address", address}, {"public_key", publicKey}, {"egress", egress},
	} {
		entry.Content = append(entry.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pair[0]},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pair[1]})
	}

	// The entry goes into the first file that already has a devices key, so the
	// layout the operator chose is kept rather than second-guessed. An empty or null
	// list is turned into a block-style one; appending to `[]` in flow style would be
	// valid YAML that no longer looks like the rest of the file.
	for _, path := range paths {
		document, err := readDocument(path)
		if err != nil || len(document.Content) == 0 {
			continue
		}
		list := findValue(document.Content[0], "devices")
		if list == nil {
			continue
		}
		if list.Kind != yaml.SequenceNode {
			*list = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		}
		if len(list.Content) == 0 {
			list.Style = 0
		}
		list.Content = append(list.Content, entry)
		return writeDocument(path, document)
	}

	// No file holds devices yet: start the list in the preferred file, which is
	// devices.yaml for a directory layout and the file itself otherwise.
	path := paths[0]
	document, err := readDocument(path)
	if os.IsNotExist(err) || (err == nil && len(document.Content) == 0) {
		document = &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{
			{Kind: yaml.MappingNode, Tag: "!!map"},
		}}
	} else if err != nil {
		return err
	}
	root := document.Content[0]
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "devices"},
		&yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{entry}})
	return writeDocument(path, document)
}

// RemoveDevice drops a device entry. It exists as AddDevice's revert: an entry that
// fails validation must leave the file as it was found.
func (e Editor) RemoveDevice(id string) error {
	release, err := e.lock()
	if err != nil {
		return err
	}
	defer release()
	for _, path := range e.deviceFiles() {
		document, err := readDocument(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		list := documentList(document, "devices")
		if list == nil {
			continue
		}
		for index, entry := range list.Content {
			if value := findValue(entry, "id"); value != nil && value.Value == id {
				list.Content = append(list.Content[:index], list.Content[index+1:]...)
				return writeDocument(path, document)
			}
		}
	}
	return fmt.Errorf("no device %q in %s", id, e.Root)
}

// documentList returns a top-level sequence by key, nil when absent.
func documentList(document *yaml.Node, section string) *yaml.Node {
	if len(document.Content) == 0 {
		return nil
	}
	list := findValue(document.Content[0], section)
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	return list
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
	// Atomic on purpose: this file is the hub's configuration, and a crash midway
	// through a plain write would leave half a document where the whole one was.
	return runtimeadapter.AtomicWrite(path, []byte(builder.String()), 0o600)
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
