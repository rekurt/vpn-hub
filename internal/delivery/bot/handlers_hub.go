package bot

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	configadapter "vpn-hub/internal/adapters/config"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
)

const (
	msgHubFieldEndpoint            MessageID = "hub/field_endpoint"
	msgHubFieldDNS                 MessageID = "hub/field_dns"
	msgHubFieldClientNetwork       MessageID = "hub/field_client_network"
	msgHubFieldUnknown             MessageID = "hub/field_unknown"
	msgHubEditPrompt               MessageID = "hub/edit_prompt"
	msgAWGSetPrompt                MessageID = "hub/awg_set_prompt"
	msgAWGParameterRequired        MessageID = "hub/awg_parameter_required"
	msgExportConfirm               MessageID = "hub/export_confirm"
	msgExportReadFailure           MessageID = "hub/export_read_failure"
	msgExportSendFailure           MessageID = "hub/export_send_failure"
	msgExportSummary               MessageID = "hub/export_summary"
	msgExportStarted               MessageID = "hub/export_started"
	msgValidationEndpoint          MessageID = "validation/hub_endpoint"
	msgValidationPort              MessageID = "validation/hub_port"
	msgValidationIPAddress         MessageID = "validation/hub_ip_address"
	msgValidationCIDR              MessageID = "validation/hub_cidr"
	msgValidationRetry             MessageID = "validation/retry"
	msgFailureHubFieldWrite        MessageID = "failure/hub_field_write"
	msgRevertHubInvalid            MessageID = "revert/hub_invalid"
	msgHubFieldChanged             MessageID = "hub/field_changed"
	msgAWGFieldsRequired           MessageID = "hub/awg_fields_required"
	msgAWGUnknownParameter         MessageID = "hub/awg_unknown_parameter"
	msgAWGValueNumeric             MessageID = "hub/awg_value_numeric"
	msgFailureAWGWrite             MessageID = "failure/awg_write"
	msgAWGParameterSaved           MessageID = "hub/awg_parameter_saved"
	msgAWGAfterChange              MessageID = "hub/awg_after_change"
	msgAWGParameterMissing         MessageID = "hub/awg_parameter_missing"
	msgAWGParameterRemoved         MessageID = "hub/awg_parameter_removed"
	msgKeyRotationWarning          MessageID = "hub/key_rotation_warning"
	msgKeyRotationConfirm          MessageID = "hub/key_rotation_confirm"
	msgKeyRotationStarting         MessageID = "hub/key_rotation_starting"
	msgFailureKeyRotationStart     MessageID = "failure/key_rotation_start"
	msgKeyRotationStarted          MessageID = "hub/key_rotation_started"
	msgKeyRotationConfigUnreadable MessageID = "hub/key_rotation_config_unreadable"
	msgKeyRotationInterrupted      MessageID = "hub/key_rotation_interrupted"
	msgRotationOldProfilesInvalid  MessageID = "hub/key_rotation_old_profiles_invalid"
	msgKeyRotationDelivered        MessageID = "hub/key_rotation_delivered"
	msgKeyRotationPending          MessageID = "hub/key_rotation_pending"
	msgKeyRotationPreviousSaved    MessageID = "hub/key_rotation_previous_saved"
	msgKeyRotationGenerateFailed   MessageID = "hub/key_rotation_generate_failed"
	msgKeyRotationUpdatingConfig   MessageID = "hub/key_rotation_updating_config"
	msgKeyRotationConfigMismatch   MessageID = "hub/key_rotation_config_mismatch"
	msgKeyRotationStageConfigCheck MessageID = "hub/key_rotation_stage_config_check"
	msgRotationStageDeviceKeygen   MessageID = "hub/key_rotation_stage_device_generate"
	msgKeyRotationStageDeviceWrite MessageID = "hub/key_rotation_stage_device_write"
	msgKeyRotationStageProfileSave MessageID = "hub/key_rotation_stage_profile_save"
	msgKeyRotationStageProfileSend MessageID = "hub/key_rotation_stage_profile_send"
	msgKeyRotationStageFinalCheck  MessageID = "hub/key_rotation_stage_final_check"
	msgReasonProfileSendFailed     MessageID = "reason/profile_send_failed"
	msgKeyRotationComplete         MessageID = "hub/key_rotation_complete"
	msgKeyRotationDetailsBelow     MessageID = "hub/key_rotation_details_below"
	msgButtonToDeploy              MessageID = "button/to_deploy"
	msgProbeKindUnknown            MessageID = "probe/kind_unknown"
	msgProbePrompt                 MessageID = "probe/prompt"
	msgProbeInvalidRetry           MessageID = "probe/invalid_retry"
	msgFailureProbeWrite           MessageID = "failure/probe_write"
	msgRevertProbeInvalid          MessageID = "revert/probe_invalid"
	msgRevertProbeRemoveInvalid    MessageID = "revert/probe_remove_invalid"
	msgProbeRemoved                MessageID = "probe/removed"
)

var hubFieldTitles = map[string]MessageID{
	"endpoint":    msgHubFieldEndpoint,
	"dns_address": msgHubFieldDNS,
	"client_cidr": msgHubFieldClientNetwork,
}

func (b *Bot) buildHub(ctx context.Context) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure(b.L, b.text(msgFailureConfigUnreadable), err)
	}
	return scr(renderHub(b.L, cfg.Hub))
}

func (b *Bot) routeHub(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildHub(ctx))
	case "x":
		b.dialogs.clear()
		return b.show(ctx, cb, b.buildHub(ctx))
	case "e":
		if len(args) < 1 || hubFieldTitles[args[0]] == "" {
			return result{toast: b.text(msgHubFieldUnknown)}
		}
		field := args[0]
		b.dialogs.start(dialogHubEdit, map[string]string{"field": field})
		return b.show(ctx, cb, screen{
			text:   b.text(msgHubEditPrompt, esc(b.text(hubFieldTitles[field]))),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "hub:x")}),
		})
	case "aa":
		b.dialogs.start(dialogAWGSet, nil)
		return b.show(ctx, cb, screen{
			text:   b.text(msgAWGSetPrompt),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "hub:x")}),
		})
	case "ad":
		if len(args) < 1 {
			return result{toast: b.text(msgAWGParameterRequired)}
		}
		return b.removeAWGParameter(ctx, cb, args[0])
	case "rk":
		return b.routeKeyRotation(ctx, cb, args)
	case "dl":
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			b.text(msgExportConfirm),
			"hub:dl!", "hub")))
	case "dl!":
		return b.exportConfig(ctx)
	default:
		return result{toast: b.text(msgUnknownButton)}
	}
}

// exportConfig sends the YAML configuration files as documents: the chat becomes
// an ad-hoc backup and a way to read the config away from SSH. Provider files and
// keys stay on the host -- the config names them, which is exactly enough. The
// uploads run in the background so a slow send does not stall the update loop.
func (b *Bot) exportConfig(ctx context.Context) result {
	paths := []string{b.ConfigPath}
	if configadapter.IsDirectory(b.ConfigPath) {
		paths = []string{filepath.Join(b.ConfigPath, "hub.yaml")}
		if _, err := os.Stat(filepath.Join(b.ConfigPath, "devices.yaml")); err == nil {
			paths = append(paths, filepath.Join(b.ConfigPath, "devices.yaml"))
		}
		if tunnels, err := configadapter.TunnelFiles(b.ConfigPath); err == nil {
			paths = append(paths, tunnels...)
		}
	}

	b.spawn("export-config", func() {
		sent := 0
		for _, path := range paths {
			content, err := os.ReadFile(path)
			if err != nil {
				b.send(ctx, b.text(msgExportReadFailure, esc(path), esc(err.Error())), nil)
				continue
			}
			if _, err := b.API.SendDocument(ctx, b.Cfg.AdminID, filepath.Base(path), content,
				"📦 <code>"+esc(path)+"</code>"); err != nil {
				b.send(ctx, b.text(msgExportSendFailure, esc(path), esc(err.Error())), nil)
				continue
			}
			sent++
		}
		b.send(ctx, b.text(msgExportSummary, sent, len(paths)),
			keyboard([]tg.InlineKeyboardButton{btn("⚙️ "+b.text(msgButtonHub), "hub")}))
	})
	return result{toast: b.text(msgExportStarted)}
}

// validateHubField pre-checks a value so the dialog can complain precisely; the
// authoritative check is still LoadAndValidate after the write.
type hubValidation struct {
	id   MessageID
	args []any
}

func validateHubField(field, value string) *hubValidation {
	switch field {
	case "endpoint":
		host, port, err := net.SplitHostPort(value)
		if err != nil || host == "" {
			return &hubValidation{id: msgValidationEndpoint}
		}
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return &hubValidation{id: msgValidationPort, args: []any{esc(port)}}
		}
	case "dns_address":
		if _, err := netip.ParseAddr(value); err != nil {
			return &hubValidation{id: msgValidationIPAddress, args: []any{esc(value)}}
		}
	case "client_cidr":
		if _, err := netip.ParsePrefix(value); err != nil {
			return &hubValidation{id: msgValidationCIDR, args: []any{esc(value)}}
		}
	}
	return nil
}

func (b *Bot) handleHubEditInput(ctx context.Context, dialog *dialog, text string) {
	field := dialog.data["field"]
	if validation := validateHubField(field, text); validation != nil {
		b.send(ctx, b.text(msgValidationRetry, b.text(validation.id, validation.args...)), nil)
		return
	}
	b.dialogs.clear()

	release := b.claimForDialog(ctx, newOperation(msgOperationHubEdit, field))
	if release == nil {
		return
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.sendScreen(ctx, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
		return
	}
	previous := map[string]string{
		"endpoint":    cfg.Hub.Endpoint,
		"dns_address": cfg.Hub.DNSAddress,
		"client_cidr": cfg.Hub.ClientCIDR,
	}[field]

	if err := b.Editor.SetHubField(field, text); err != nil {
		b.sendScreen(ctx, renderFailure(b.L, b.text(msgFailureHubFieldWrite), err))
		return
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		b.sendScreen(ctx, revertEdit(b.L, b.text(msgRevertHubInvalid), err, func() error {
			return b.Editor.SetHubField(field, previous)
		}))
		return
	}
	b.sendScreen(ctx, screen{
		text: b.text(msgHubFieldChanged, esc(b.text(hubFieldTitles[field])), esc(previous), esc(text)),
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("📱 "+b.text(MsgButtonDevices), "dev"), btn("🚀 "+b.text(msgButtonDeploy), "dep")},
			[]tg.InlineKeyboardButton{btn("⚙️ "+b.text(msgButtonHub), "hub")},
		),
	})
}

func (b *Bot) handleAWGSetInput(ctx context.Context, _ *dialog, text string) {
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '=' })
	if len(fields) != 2 {
		b.send(ctx, b.text(msgAWGFieldsRequired), nil)
		return
	}
	name, value := fields[0], fields[1]
	canonical, known := domain.CanonicalAWGParameter(name)
	if !known {
		b.send(ctx, b.text(msgAWGUnknownParameter, esc(name)), nil)
		return
	}
	if _, err := strconv.Atoi(value); err != nil {
		b.send(ctx, b.text(msgAWGValueNumeric), nil)
		return
	}
	b.dialogs.clear()

	release := b.claimForDialog(ctx, newOperation(msgOperationAWGSet, canonical))
	if release == nil {
		return
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.sendScreen(ctx, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
		return
	}
	// The config decodes keys lower-cased; write the same shape it already holds.
	key := strings.ToLower(canonical)
	previous, existed := cfg.Hub.AWGInterface[key]

	if err := b.Editor.SetHubMapField("awg_interface", key, value); err != nil {
		b.sendScreen(ctx, renderFailure(b.L, b.text(msgFailureAWGWrite), err))
		return
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		b.sendScreen(ctx, revertEdit(b.L, b.text(msgRevertHubInvalid), err, func() error {
			if existed {
				return b.Editor.SetHubMapField("awg_interface", key, previous)
			}
			return b.Editor.RemoveHubMapField("awg_interface", key)
		}))
		return
	}
	b.sendScreen(ctx, b.afterHubChange(b.text(msgAWGParameterSaved, esc(canonical), esc(value))))
}

// afterHubChange reminds that obfuscation parameters live in client profiles too.
func (b *Bot) afterHubChange(text string) screen {
	return screen{
		text: text + "\n\n" + b.text(msgAWGAfterChange),
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("📱 "+b.text(MsgButtonDevices), "dev"), btn("🚀 "+b.text(msgButtonDeploy), "dep")},
			[]tg.InlineKeyboardButton{btn("⚙️ "+b.text(msgButtonHub), "hub")},
		),
	}
}

func (b *Bot) removeAWGParameter(ctx context.Context, cb *tg.CallbackQuery, key string) result {
	release, busy := b.claim(newOperation(msgOperationAWGRemove, key))
	if busy != nil {
		return *busy
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
	}
	previous, existed := cfg.Hub.AWGInterface[key]
	if !existed {
		return result{toast: b.text(msgAWGParameterMissing), alert: true}
	}

	if err := b.Editor.RemoveHubMapField("awg_interface", key); err != nil {
		b.logf("remove AWG parameter %s: %v", key, err)
		return result{toast: b.text(msgFailureAWGWrite), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		return b.show(ctx, cb, revertEdit(b.L, b.text(msgRevertHubInvalid), err, func() error {
			return b.Editor.SetHubMapField("awg_interface", key, previous)
		}))
	}
	outcome := b.show(ctx, cb, b.buildHub(ctx))
	name, _ := domain.CanonicalAWGParameter(key)
	outcome.toast = b.text(msgAWGParameterRemoved, name)
	return outcome
}

// --- Hub key rotation ------------------------------------------------------

func (b *Bot) routeKeyRotation(ctx context.Context, cb *tg.CallbackQuery, args []string) result {
	if len(args) == 0 {
		return b.show(ctx, cb, screen{
			text: b.text(msgKeyRotationWarning),
			markup: keyboard(
				[]tg.InlineKeyboardButton{btn(b.text(msgKeyRotationConfirm), "hub:rk:go"), btn(b.text(MsgConfirmNo), "hub")},
			),
		})
	}
	if args[0] != "go" {
		return result{toast: b.text(msgUnknownButton)}
	}

	release, busy := b.claim(newOperation(msgOperationHubKeyRotation))
	if busy != nil {
		return *busy
	}

	progress, err := b.API.SendMessage(ctx, b.Cfg.AdminID, b.text(msgKeyRotationStarting), nil)
	if err != nil {
		release()
		b.logf("start key rotation: %v", err)
		return result{toast: b.text(msgFailureKeyRotationStart), alert: true}
	}

	b.spawn("key-rotation", func() {
		defer release()
		b.rotateHubKey(ctx, progress.Chat.ID, progress.ID)
	})
	return result{toast: b.text(msgKeyRotationStarted)}
}

// rotateHubKey is the one flow where half-done is the dangerous state, so every
// step reports precisely what has and has not happened.
func (b *Bot) rotateHubKey(ctx context.Context, chatID, messageID int64) {
	edit := func(text string) {
		if err := b.API.EditMessageText(ctx, chatID, messageID, text, nil); err != nil {
			b.logf("rotation edit: %v", err)
		}
	}

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		edit(b.text(msgKeyRotationConfigUnreadable, esc(err.Error())))
		return
	}
	allDevices := make([]string, 0, len(cfg.Devices))
	for _, device := range cfg.Devices {
		allDevices = append(allDevices, device.ID)
	}

	// fail is called once the hub key has already changed, so every device's old
	// profile is dead regardless of how far the loop got. It names which profiles
	// were delivered and which the admin must re-issue by hand, because guessing
	// wrong here means a device silently offline.
	fail := func(stage string, cause error, delivered []string) {
		var b2 strings.Builder
		b2.WriteString(b.text(msgKeyRotationInterrupted, esc(stage), esc(cause.Error())))
		b2.WriteString(b.text(msgRotationOldProfilesInvalid))
		if len(delivered) > 0 {
			b2.WriteString(b.text(msgKeyRotationDelivered, esc(strings.Join(delivered, ", "))))
		}
		pending := subtract(allDevices, delivered)
		if len(pending) > 0 {
			b2.WriteString(b.text(msgKeyRotationPending, esc(strings.Join(pending, ", "))))
		}
		b2.WriteString(b.text(msgKeyRotationPreviousSaved))
		b.sendScreen(ctx, screen{text: b2.String(), markup: keyboard(
			[]tg.InlineKeyboardButton{btn("📱 "+b.text(MsgButtonDevices), "dev"), btn("📊 "+b.text(MsgButtonStatus), "st")},
		)})
	}

	publicKey, err := b.Keys.Rotate()
	if err != nil {
		edit(b.text(msgKeyRotationGenerateFailed, esc(err.Error())))
		return
	}
	edit(b.text(msgKeyRotationUpdatingConfig))

	if err := b.Editor.SetHubField("server_public_key", publicKey); err != nil {
		// The one irrecoverable-by-bot spot: the on-disk key is new but the config
		// still names the old public key, so nothing matches until they do.
		edit(b.text(msgKeyRotationConfigMismatch, esc(err.Error())))
		return
	}

	// Reload so profiles carry the new hub public key (it is the [Peer] key in
	// every client profile). Device keys are still the old values here, which
	// validation accepts -- it does not cross-check them against the hub key.
	withNewKey, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		fail(b.text(msgKeyRotationStageConfigCheck), err, nil)
		return
	}

	// Each device's key is written and its profile delivered in the same step, so
	// a private key never lives only in memory across a later failure.
	var delivered []string
	for _, device := range cfg.Devices {
		privateKey, devicePublic, err := domain.GenerateX25519KeyPair()
		if err != nil {
			fail(b.text(msgRotationStageDeviceKeygen, device.ID), err, delivered)
			return
		}
		if err := b.Editor.SetDeviceField(device.ID, "public_key", devicePublic); err != nil {
			fail(b.text(msgKeyRotationStageDeviceWrite, device.ID), err, delivered)
			return
		}
		if err := b.saveProfileKey(ctx, device.ID, privateKey); err != nil {
			fail(b.text(msgKeyRotationStageProfileSave, device.ID), err, delivered)
			return
		}
		if outcome := b.sendProfile(ctx, withNewKey.Hub, device.ID, device.Address, privateKey); outcome != nil {
			fail(b.text(msgKeyRotationStageProfileSend, device.ID), fmt.Errorf("%s", b.text(msgReasonProfileSendFailed)), delivered)
			return
		}
		delivered = append(delivered, device.ID)
	}

	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		fail(b.text(msgKeyRotationStageFinalCheck), err, delivered)
		return
	}

	b.sendScreen(ctx, screen{
		text: b.text(msgKeyRotationComplete),
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("🚀 "+b.text(msgButtonToDeploy), "dep")},
			backRow(b.L),
		),
	})
	edit(b.text(msgKeyRotationDetailsBelow))
}

// subtract returns the elements of all that are not in the removed set, order
// preserved.
func subtract(all, removed []string) []string {
	gone := make(map[string]bool, len(removed))
	for _, id := range removed {
		gone[id] = true
	}
	var kept []string
	for _, id := range all {
		if !gone[id] {
			kept = append(kept, id)
		}
	}
	return kept
}

// --- Tunnel probes ---------------------------------------------------------

func probeKind(key string) (field, title, example string, ok bool) {
	for _, kind := range probeKinds {
		if kind.Key == key {
			return kind.Field, kind.Title, kind.Example, true
		}
	}
	return "", "", "", false
}

// probeValue reads the configured value of one probe kind off a HealthCheck, so a
// removal can be reverted with the value it displaced.
func probeValue(h domain.HealthCheck, kindKey string) string {
	switch kindKey {
	case "tcp":
		return h.TCPAddress
	case "https":
		return h.HTTPSURL
	case "dns":
		return h.DNSName
	}
	return ""
}

func (b *Bot) buildProbes(ctx context.Context, tunnelID string) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure(b.L, b.text(msgFailureConfigUnreadable), err)
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == tunnelID {
			return scr(renderProbes(b.L, tunnelID, tunnel.Health))
		}
	}
	return renderFailure(b.L, b.text(msgFailureTunnelNotFound), fmt.Errorf("%s", b.text(msgReasonTunnelNotFound, tunnelID)))
}

func (b *Bot) startProbeDialog(ctx context.Context, cb *tg.CallbackQuery, tunnelID, kindKey string) result {
	_, title, example, ok := probeKind(kindKey)
	if !ok {
		return result{toast: b.text(msgProbeKindUnknown)}
	}
	b.dialogs.start(dialogProbeSet, map[string]string{"tunnel": tunnelID, "kind": kindKey})
	return b.show(ctx, cb, screen{
		text:   b.text(msgProbePrompt, esc(title), esc(tunnelID), esc(example)),
		markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "tun:pr:"+tunnelID)}),
	})
}

func (b *Bot) handleProbeSetInput(ctx context.Context, dialog *dialog, text string) {
	tunnelID, kindKey := dialog.data["tunnel"], dialog.data["kind"]
	field, _, _, ok := probeKind(kindKey)
	if !ok {
		b.dialogs.clear()
		return
	}
	// Pre-validate with the domain's own rules -- these values become root-run
	// command arguments on the host, so the rules are strict on purpose.
	trial := domain.HealthCheck{}
	switch field {
	case "tcp_address":
		trial.TCPAddress = text
	case "https_url":
		trial.HTTPSURL = text
	case "dns_name":
		trial.DNSName = text
	}
	if err := trial.Validate(); err != nil {
		b.logf("validate %s probe for %s: %v", kindKey, tunnelID, err)
		b.send(ctx, b.text(msgProbeInvalidRetry), nil)
		return
	}
	b.dialogs.clear()

	release := b.claimForDialog(ctx, newOperation(msgOperationProbeSet, kindKey, tunnelID))
	if release == nil {
		return
	}
	defer release()

	if err := b.Editor.SetTunnelMapField(tunnelID, "health", field, text); err != nil {
		b.sendScreen(ctx, renderFailure(b.L, b.text(msgFailureProbeWrite), err))
		return
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		b.sendScreen(ctx, revertEdit(b.L, b.text(msgRevertProbeInvalid), err, func() error {
			return b.Editor.RemoveTunnelMapField(tunnelID, "health", field)
		}))
		return
	}
	b.sendScreen(ctx, b.buildProbes(ctx, tunnelID))
}

func (b *Bot) removeProbe(ctx context.Context, cb *tg.CallbackQuery, tunnelID, kindKey string) result {
	field, title, _, ok := probeKind(kindKey)
	if !ok {
		return result{toast: b.text(msgProbeKindUnknown)}
	}
	release, busy := b.claim(newOperation(msgOperationProbeRemove, kindKey, tunnelID))
	if busy != nil {
		return *busy
	}
	defer release()

	// Capture the current value so the removal can be undone if it turns the config
	// invalid -- symmetric to setting a probe (handleProbeSetInput reverts too). The
	// config is valid now, so this read succeeds; without the revert a removal that
	// broke validation would leave the config unloadable and the whole UI broken.
	previous := ""
	if cfg, err := b.Service.LoadAndValidate(ctx); err == nil {
		for _, tunnel := range cfg.Tunnels {
			if tunnel.ID == tunnelID {
				previous = probeValue(tunnel.Health, kindKey)
			}
		}
	}

	if err := b.Editor.RemoveTunnelMapField(tunnelID, "health", field); err != nil {
		b.logf("remove %s probe for %s: %v", kindKey, tunnelID, err)
		return result{toast: b.text(msgFailureProbeWrite), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		return b.show(ctx, cb, revertEdit(b.L, b.text(msgRevertProbeRemoveInvalid), err, func() error {
			if previous == "" {
				// Nothing to put back: the probe had no value to begin with.
				return nil
			}
			return b.Editor.SetTunnelMapField(tunnelID, "health", field, previous)
		}))
	}
	outcome := b.show(ctx, cb, b.buildProbes(ctx, tunnelID))
	outcome.toast = b.text(msgProbeRemoved, title)
	return outcome
}
