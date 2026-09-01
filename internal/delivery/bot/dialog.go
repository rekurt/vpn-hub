package bot

import (
	"context"
	"sync"
)

// Dialog kinds. A dialog is a short question-and-answer exchange where the next
// plain-text message is an answer rather than a command.
const (
	dialogDeviceAdd = "device-add"
	dialogRouteAdd  = "route-add"
	dialogZoneAdd   = "zone-add"
	dialogHubEdit   = "hub-edit"
	dialogAWGSet    = "awg-set"
	dialogProbeSet  = "probe-set"
	dialogClientACL = "client-acl"
)

// dialog is the state of one unfinished exchange. There is exactly one admin, so at
// most one dialog exists; starting a new one abandons the old, and /cancel clears it.
type dialog struct {
	kind string
	step int
	data map[string]string
}

type dialogs struct {
	mu     sync.Mutex
	active *dialog
}

func (d *dialogs) start(kind string, data map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if data == nil {
		data = map[string]string{}
	}
	d.active = &dialog{kind: kind, data: data}
}

// current returns the active dialog; the caller mutates it in place.
func (d *dialogs) current() *dialog {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active
}

func (d *dialogs) clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active = nil
}

// handleDialogInput routes a plain-text message into the active dialog.
func (b *Bot) handleDialogInput(ctx context.Context, text string) {
	dialog := b.dialogs.current()
	if dialog == nil {
		return
	}
	switch dialog.kind {
	case dialogDeviceAdd:
		b.handleDeviceAddInput(ctx, dialog, text)
	case dialogRouteAdd, dialogZoneAdd:
		b.handleListAddInput(ctx, dialog, text)
	case dialogHubEdit:
		b.handleHubEditInput(ctx, dialog, text)
	case dialogAWGSet:
		b.handleAWGSetInput(ctx, dialog, text)
	case dialogProbeSet:
		b.handleProbeSetInput(ctx, dialog, text)
	case dialogClientACL:
		b.handleClientACLInput(ctx, dialog, text)
	}
}
