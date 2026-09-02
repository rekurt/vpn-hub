package bot

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"sort"

	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
)

const (
	msgFailureConfigUnreadable     MessageID = "failure/config_unreadable"
	msgFailureDeviceNotFound       MessageID = "failure/device_not_found"
	msgReasonDeviceNotFound        MessageID = "reason/device_not_found"
	msgDeviceRequired              MessageID = "device/required"
	msgDeviceRevokeConfirm         MessageID = "device/revoke_confirm"
	msgDeviceReissueConfirm        MessageID = "device/reissue_confirm"
	msgDeviceAlreadySelected       MessageID = "device/already_selected"
	msgToastDone                   MessageID = "toast/done"
	msgOperationEgressChange       MessageID = "operation/egress_change"
	msgRevertInvalidConfig         MessageID = "revert/invalid_config"
	msgButtonToDevice              MessageID = "button/to_device"
	msgDeviceEgressChanged         MessageID = "device/egress_changed"
	msgChangeAfterDeploy           MessageID = "change/after_deploy"
	msgDeviceNewPrompt             MessageID = "device/new_prompt"
	msgDialogStale                 MessageID = "dialog/stale"
	msgAddressRequired             MessageID = "device/address_required"
	msgEgressRequired              MessageID = "device/egress_required"
	msgDeviceEgressStep            MessageID = "device/egress_step"
	msgDeviceIDInvalid             MessageID = "device/id_invalid"
	msgDeviceAddressStep           MessageID = "device/address_step"
	msgDeviceAddressSuggestion     MessageID = "device/address_suggestion"
	msgButtonUseAddress            MessageID = "button/use_address"
	msgRetryOrCancel               MessageID = "dialog/retry_or_cancel"
	msgDeviceChooseEgress          MessageID = "device/choose_egress"
	msgHostRouteExampleError       MessageID = "device/host_route_example_error"
	msgHostRouteBitsError          MessageID = "device/host_route_bits_error"
	msgOperationDeviceAdd          MessageID = "operation/device_add"
	msgFailureGenerateKey          MessageID = "failure/generate_key"
	msgFailureDeviceAdd            MessageID = "failure/device_add"
	msgRevertNewDeviceInvalid      MessageID = "revert/new_device_invalid"
	msgRevertProfileKeySaveAdd     MessageID = "revert/profile_key_save_add"
	msgDeviceAdded                 MessageID = "device/added"
	msgToastDeviceAdded            MessageID = "toast/device_added"
	msgProfileStoreNotConfigured   MessageID = "profile/store_not_configured"
	msgOperationProfileSend        MessageID = "operation/profile_send"
	msgFailureRevocationCheck      MessageID = "failure/revocation_check"
	msgRevokedNeedsReissue         MessageID = "profile/revoked_needs_reissue"
	msgProfileStoreUnavailable     MessageID = "profile/store_unavailable"
	msgOldProfileMissing           MessageID = "profile/old_missing"
	msgFailureStoredProfileRead    MessageID = "failure/stored_profile_read"
	msgFailureStoredProfileCorrupt MessageID = "failure/stored_profile_corrupt"
	msgProfileKeyChanged           MessageID = "profile/key_changed"
	msgToastProfileSent            MessageID = "toast/profile_sent"
	msgFailureProfileRender        MessageID = "failure/profile_render"
	msgToastError                  MessageID = "toast/error"
	msgProfileCaption              MessageID = "profile/caption"
	msgFailureProfileSend          MessageID = "failure/profile_send"
	msgProfileQRFailed             MessageID = "profile/qr_failed"
	msgProfileQRCaption            MessageID = "profile/qr_caption"
	msgFallbackFailed              MessageID = "profile/fallback_failed"
	msgFallbackUDP443Caption       MessageID = "profile/fallback_udp443_caption"
	msgFallbackReality             MessageID = "profile/fallback_reality"
	msgFallbackRealityCaption      MessageID = "profile/fallback_reality_caption"
	msgOperationProfileReissue     MessageID = "operation/profile_reissue"
	msgFailureKeyWrite             MessageID = "failure/key_write"
	msgRevertProfileKeySaveReissue MessageID = "revert/profile_key_save_reissue"
	msgRevocationRemoveFailed      MessageID = "profile/revocation_remove_failed"
	msgDeviceReissued              MessageID = "device/reissued"
	msgToastProfileReissued        MessageID = "toast/profile_reissued"
	msgOperationDeviceRevoke       MessageID = "operation/device_revoke"
	msgDeviceRevokedSuccess        MessageID = "device/revoked_success"
	msgToastDeviceRevoked          MessageID = "toast/device_revoked"
)

func (b *Bot) deviceEntries(ctx context.Context) ([]deviceEntry, error) {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return nil, err
	}
	revoked, err := b.Revocations.Load(ctx)
	if err != nil {
		return nil, err
	}
	revokedSet := map[string]bool{}
	for _, id := range revoked {
		revokedSet[id] = true
	}

	// The live interface tells who is actually connected. Failing to observe it
	// (workstation, stopped hub) degrades presence to unknown, not the screen.
	peers := map[string]domain.PeerObservation{}
	if observed, err := b.Peers.Observe(ctx, application.IngressInterface); err == nil {
		for _, peer := range observed.Peers {
			peers[peer.PublicKey] = peer
		}
	}

	now := b.Now()
	entries := make([]deviceEntry, 0, len(cfg.Devices))
	for _, device := range cfg.Devices {
		entry := deviceEntry{
			ID: device.ID, Address: device.Address, PublicKey: device.PublicKey,
			Egress: device.Egress, Revoked: revokedSet[device.ID], Now: now,
		}
		if peer, exists := peers[device.PublicKey]; exists {
			entry.Peer = &peer
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

func (b *Bot) buildDevices(ctx context.Context) screen {
	entries, err := b.deviceEntries(ctx)
	if err != nil {
		return renderFailure(b.L, b.text(msgFailureConfigUnreadable), err)
	}
	return scr(renderDevices(b.L, entries))
}

func (b *Bot) buildDeviceCard(ctx context.Context, deviceID string) screen {
	entries, err := b.deviceEntries(ctx)
	if err != nil {
		return renderFailure(b.L, b.text(msgFailureConfigUnreadable), err)
	}
	for _, entry := range entries {
		if entry.ID == deviceID {
			return scr(renderDeviceCard(b.L, entry))
		}
	}
	return renderFailure(b.L, b.text(msgFailureDeviceNotFound), errors.New(b.text(msgReasonDeviceNotFound, deviceID)))
}

// egressChoices lists what a device may leave through: enabled egress tunnels and
// the direct path.
func (b *Bot) egressChoices(cfg domain.Config) []string {
	choices := []string{}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.Role == domain.RoleEgress && tunnel.IsEnabled() {
			choices = append(choices, tunnel.ID)
		}
	}
	sort.Strings(choices)
	return append(choices, domain.EgressDirect)
}

func (b *Bot) routeDevices(ctx context.Context, cb *tg.CallbackQuery, action string, args []string) result {
	switch action {
	case "":
		return b.show(ctx, cb, b.buildDevices(ctx))
	case "x":
		b.dialogs.clear()
		return b.show(ctx, cb, b.buildDevices(ctx))
	case "c":
		if len(args) < 1 {
			return result{toast: b.text(msgDeviceRequired)}
		}
		return b.show(ctx, cb, b.buildDeviceCard(ctx, args[0]))
	case "eg":
		return b.routeDeviceEgress(ctx, cb, args)
	case "add":
		return b.routeDeviceAdd(ctx, cb, args)
	case "rv":
		if len(args) < 1 {
			return result{toast: b.text(msgDeviceRequired)}
		}
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			b.text(msgDeviceRevokeConfirm, esc(args[0])),
			"dev:rv!:"+args[0], "dev:c:"+args[0])))
	case "rv!":
		if len(args) < 1 {
			return result{toast: b.text(msgDeviceRequired)}
		}
		return b.revokeDevice(ctx, cb, args[0])
	case "re":
		if len(args) < 1 {
			return result{toast: b.text(msgDeviceRequired)}
		}
		return b.show(ctx, cb, scr(renderConfirm(b.L,
			b.text(msgDeviceReissueConfirm, esc(args[0])),
			"dev:re!:"+args[0], "dev:c:"+args[0])))
	case "re!":
		if len(args) < 1 {
			return result{toast: b.text(msgDeviceRequired)}
		}
		return b.reissueDevice(ctx, cb, args[0])
	case "pr":
		if len(args) < 1 {
			return result{toast: b.text(msgDeviceRequired)}
		}
		return b.sendCurrentProfile(ctx, cb, args[0])
	default:
		return result{toast: b.text(msgUnknownButton)}
	}
}

// --- set-egress ------------------------------------------------------------

func (b *Bot) routeDeviceEgress(ctx context.Context, cb *tg.CallbackQuery, args []string) result {
	if len(args) < 1 {
		return result{toast: b.text(msgDeviceRequired)}
	}
	deviceID := args[0]
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
	}
	current := ""
	for _, device := range cfg.Devices {
		if device.ID == deviceID {
			current = device.Egress
		}
	}
	if current == "" {
		return result{toast: b.text(msgFailureDeviceNotFound), alert: true}
	}

	if len(args) == 1 {
		return b.show(ctx, cb, scr(renderEgressChoice(b.L, deviceID, current, b.egressChoices(cfg))))
	}

	target := args[1]
	if target == current {
		return result{toast: b.text(msgDeviceAlreadySelected)}
	}
	release, busy := b.claim(b.text(msgOperationEgressChange, deviceID))
	if busy != nil {
		return *busy
	}
	defer release()

	// The same write-validate-revert dance as `hubctl device set-egress`: the
	// operator hears about a config that stopped validating now, not at deploy.
	if err := b.Editor.SetDeviceField(deviceID, "egress", target); err != nil {
		return result{toast: b.text(msgOperationFailed, err.Error()), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		view := revertEdit(b.L, b.text(msgRevertInvalidConfig), err, func() error {
			return b.Editor.SetDeviceField(deviceID, "egress", current)
		})
		return b.show(ctx, cb, screen{
			text:   view.text,
			markup: keyboard([]tg.InlineKeyboardButton{btn("⬅️ "+b.text(msgButtonToDevice), "dev:c:"+deviceID)}),
		})
	}
	outcome := b.show(ctx, cb, b.afterConfigChange(b.text(msgDeviceEgressChanged, esc(deviceID), esc(target)), b.backToDevices()))
	outcome.toast = b.text(msgToastDone)
	return outcome
}

// afterConfigChange reminds that edits do nothing until deployed -- the same
// sentence hubctl prints, as buttons. The back row names the section the change was
// made in, so the operator returns where they were rather than always to devices.
func (b *Bot) afterConfigChange(text string, back []tg.InlineKeyboardButton) screen {
	return screen{
		text: text + "\n\n" + b.text(msgChangeAfterDeploy),
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("🚀 "+b.text(msgButtonDeploy), "dep")},
			back,
		),
	}
}

func (b *Bot) backToDevices() []tg.InlineKeyboardButton {
	return []tg.InlineKeyboardButton{btn("📱 "+b.text(MsgButtonDevices), "dev"), btn("🏠 "+b.text(msgButtonMenu), "m")}
}

func (b *Bot) backToTunnels() []tg.InlineKeyboardButton {
	return []tg.InlineKeyboardButton{btn("🚇 "+b.text(msgButtonTunnels), "tun"), btn("🏠 "+b.text(msgButtonMenu), "m")}
}

// --- add -------------------------------------------------------------------

var deviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

func (b *Bot) routeDeviceAdd(ctx context.Context, cb *tg.CallbackQuery, args []string) result {
	if len(args) == 0 {
		b.dialogs.start(dialogDeviceAdd, nil)
		return b.show(ctx, cb, screen{
			text:   b.text(msgDeviceNewPrompt),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "dev:x")}),
		})
	}

	dialog := b.dialogs.current()
	if dialog == nil || dialog.kind != dialogDeviceAdd {
		return result{toast: b.text(msgDialogStale), alert: true}
	}
	switch args[0] {
	case "addr":
		if len(args) < 2 {
			return result{toast: b.text(msgAddressRequired)}
		}
		dialog.data["address"] = args[1]
		dialog.step = 2
		return b.show(ctx, cb, b.deviceAddEgressStep(ctx))
	case "eg":
		if len(args) < 2 {
			return result{toast: b.text(msgEgressRequired)}
		}
		return b.finishDeviceAdd(ctx, cb, args[1])
	default:
		return result{toast: b.text(msgUnknownButton)}
	}
}

func (b *Bot) deviceAddEgressStep(ctx context.Context) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.dialogs.clear()
		return renderFailure(b.L, b.text(msgFailureConfigUnreadable), err)
	}
	var rows [][]tg.InlineKeyboardButton
	for _, egress := range b.egressChoices(cfg) {
		rows = append(rows, []tg.InlineKeyboardButton{btn(egress, "dev:add:eg:"+egress)})
	}
	rows = append(rows, []tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "dev:x")})
	return screen{
		text:   b.text(msgDeviceEgressStep),
		markup: keyboard(rows...),
	}
}

// handleDeviceAddInput consumes the dialog's text answers: the id, then the address.
func (b *Bot) handleDeviceAddInput(ctx context.Context, dialog *dialog, text string) {
	switch dialog.step {
	case 0:
		if !deviceIDPattern.MatchString(text) {
			b.send(ctx, b.text(msgDeviceIDInvalid), nil)
			return
		}
		dialog.data["id"] = text
		dialog.step = 1

		prompt := b.text(msgDeviceAddressStep, esc("10.80.0.2/32"))
		var markup *tg.InlineKeyboardMarkup
		if cfg, err := b.Service.LoadAndValidate(ctx); err == nil {
			if suggestion := nextFreeAddress(cfg); suggestion != "" {
				prompt = b.text(msgDeviceAddressSuggestion, esc(suggestion))
				markup = keyboard(
					[]tg.InlineKeyboardButton{btn(b.text(msgButtonUseAddress, suggestion), "dev:add:addr:"+suggestion)},
					[]tg.InlineKeyboardButton{btn("✖️ "+b.text(msgButtonCancel), "dev:x")},
				)
			}
		}
		b.send(ctx, prompt, markup)
	case 1:
		if err := validateHostRoute(b.L, text); err != nil {
			b.send(ctx, b.text(msgRetryOrCancel, esc(err.Error())), nil)
			return
		}
		dialog.data["address"] = text
		dialog.step = 2
		b.sendScreen(ctx, b.deviceAddEgressStep(ctx))
	default:
		b.send(ctx, b.text(msgDeviceChooseEgress), nil)
	}
}

func validateHostRoute(l Localizer, value string) error {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return errors.New(l.Text(msgHostRouteExampleError))
	}
	bits := 32
	if prefix.Addr().Is6() {
		bits = 128
	}
	if prefix.Bits() != bits {
		return errors.New(l.Text(msgHostRouteBitsError, bits))
	}
	return nil
}

// nextFreeAddress proposes the first unused host address in the client network.
func nextFreeAddress(cfg domain.Config) string {
	prefix, err := netip.ParsePrefix(cfg.Hub.ClientCIDR)
	if err != nil {
		return ""
	}
	used := map[string]bool{}
	for _, device := range cfg.Devices {
		if devicePrefix, err := netip.ParsePrefix(device.Address); err == nil {
			used[devicePrefix.Addr().String()] = true
		}
	}
	if hub, err := netip.ParseAddr(cfg.Hub.DNSAddress); err == nil {
		used[hub.String()] = true
	}

	address := prefix.Masked().Addr()
	for range 65536 {
		address = address.Next()
		if !prefix.Contains(address) {
			return ""
		}
		if used[address.String()] {
			continue
		}
		candidate := address.String() + "/32"
		if address.Is6() {
			candidate = address.String() + "/128"
		}
		// Asked of the same rule the deploy will apply, rather than repeated here.
		// The addresses a prefix cannot hand out -- its broadcast address, which the
		// hub's ingress interface makes broadcast on the link -- are a property of
		// the subnet, not of this screen, and an allocator that disagreed with
		// validation would offer a device the deploy then refuses to take.
		//
		// Ascending, so the first refusal past the last usable address ends the
		// search: nothing above it can be free.
		if err := application.ValidateProfileAddress(candidate, cfg.Hub.ClientCIDR); err != nil {
			return ""
		}
		return candidate
	}
	return ""
}

func (b *Bot) finishDeviceAdd(ctx context.Context, cb *tg.CallbackQuery, egress string) result {
	dialog := b.dialogs.current()
	if dialog == nil || dialog.kind != dialogDeviceAdd || dialog.data["id"] == "" || dialog.data["address"] == "" {
		return result{toast: b.text(msgDialogStale), alert: true}
	}
	deviceID, address := dialog.data["id"], dialog.data["address"]

	release, busy := b.claim(b.text(msgOperationDeviceAdd, deviceID))
	if busy != nil {
		return *busy
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
	}

	// The private key exists only inside this call: it goes into the profile that
	// leaves through the chat, and the hub keeps the public half in the config.
	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureGenerateKey), err))
	}
	if err := b.Editor.AddDevice(deviceID, address, publicKey, egress); err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureDeviceAdd), err))
	}
	undoAdd := func() error { return b.Editor.RemoveDevice(deviceID) }
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		return b.show(ctx, cb, revertEdit(b.L,
			b.text(msgRevertNewDeviceInvalid), err, undoAdd))
	}
	if err := b.saveProfileKey(ctx, deviceID, privateKey); err != nil {
		return b.show(ctx, cb, revertEdit(b.L,
			b.text(msgRevertProfileKeySaveAdd), err, undoAdd))
	}
	b.dialogs.clear()

	if outcome := b.sendProfile(ctx, cfg.Hub, deviceID, address, privateKey); outcome != nil {
		return *outcome
	}
	view := b.afterConfigChange(b.text(msgDeviceAdded, esc(deviceID), esc(address), esc(egress)), b.backToDevices())
	b.sendScreen(ctx, view)
	return result{toast: b.text(msgToastDeviceAdded)}
}

func (b *Bot) saveProfileKey(ctx context.Context, deviceID, privateKey string) error {
	if b.ProfileKeys == nil {
		return errors.New(b.text(msgProfileStoreNotConfigured))
	}
	return b.ProfileKeys.Save(ctx, deviceID, privateKey)
}

// sendCurrentProfile re-delivers a profile without changing the device key. A
// profile issued before key storage was introduced cannot be reconstructed, so the
// operator gets an explicit, safe reissue path instead of a different profile.
func (b *Bot) sendCurrentProfile(ctx context.Context, cb *tg.CallbackQuery, deviceID string) result {
	release, busy := b.claim(b.text(msgOperationProfileSend, deviceID))
	if busy != nil {
		return *busy
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
	}
	var device domain.Device
	for _, candidate := range cfg.Devices {
		if candidate.ID == deviceID {
			device = candidate
			break
		}
	}
	if device.ID == "" {
		return result{toast: b.text(msgFailureDeviceNotFound), alert: true}
	}
	revoked, err := b.Revocations.Load(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureRevocationCheck), err))
	}
	for _, id := range revoked {
		if id == deviceID {
			return result{toast: b.text(msgRevokedNeedsReissue), alert: true}
		}
	}
	if b.ProfileKeys == nil {
		return result{toast: b.text(msgProfileStoreUnavailable), alert: true}
	}
	privateKey, err := b.ProfileKeys.Load(ctx, deviceID)
	if errors.Is(err, runtimeadapter.ErrProfileKeyNotFound) {
		return result{toast: b.text(msgOldProfileMissing), alert: true}
	}
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureStoredProfileRead), err))
	}
	publicKey, err := domain.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureStoredProfileCorrupt), err))
	}
	if publicKey != device.PublicKey {
		return result{toast: b.text(msgProfileKeyChanged), alert: true}
	}
	if outcome := b.sendProfile(ctx, cfg.Hub, deviceID, device.Address, privateKey); outcome != nil {
		return *outcome
	}
	return result{toast: b.text(msgToastProfileSent)}
}

// sendProfile renders the client profile and delivers it as a file plus a QR code.
// A non-nil result is the failure to report.
func (b *Bot) sendProfile(ctx context.Context, hub domain.Hub, deviceID, address, privateKey string) *result {
	profile, err := b.Profiles.Render(hub, address, privateKey)
	if err != nil {
		b.sendScreen(ctx, renderFailure(b.L, b.text(msgFailureProfileRender), err))
		return &result{toast: b.text(msgToastError)}
	}
	if _, err := b.API.SendDocument(ctx, b.Cfg.AdminID, deviceID+".conf", []byte(profile),
		b.text(msgProfileCaption, esc(deviceID))); err != nil {
		b.sendScreen(ctx, renderFailure(b.L, b.text(msgFailureProfileSend), err))
		return &result{toast: b.text(msgToastError)}
	}
	// The QR code is a convenience; the profile file above already succeeded, so a
	// missing qrencode degrades politely rather than failing the whole flow.
	if image, err := b.QR.PNG(ctx, profile); err != nil {
		b.send(ctx, b.text(msgProfileQRFailed, esc(err.Error())), nil)
	} else if _, err := b.API.SendPhoto(ctx, b.Cfg.AdminID, deviceID+".png", image,
		b.text(msgProfileQRCaption)); err != nil {
		b.logf("sendPhoto: %v", err)
	}
	b.sendFallbackProfiles(ctx, hub, deviceID, address, privateKey)
	return nil
}

// sendFallbackProfiles delivers the alternative ways in, when they are configured.
//
// Every failure here is reported and stepped over: the ordinary profile has
// already been delivered, and a device that cannot use the fallback is still a
// device that works everywhere the fallback is not needed.
// fallbackFailed says a way in was not delivered, in the chat rather than the
// journal.
//
// The distinction matters more here than it looks: the ordinary profile arrives
// either way, so the screen reads as success, and an operator who was never told
// otherwise hands over a device believing it can also come in on 443. They find
// out on the network where that was the point -- which is the one place the
// journal is not.
func (b *Bot) fallbackFailed(ctx context.Context, way string, err error) {
	b.logf("%s fallback: %v", way, err)
	b.send(ctx, b.text(msgFallbackFailed, way, esc(err.Error())), nil)
}

func (b *Bot) sendFallbackProfiles(ctx context.Context, hub domain.Hub, deviceID, address, privateKey string) {
	if hub.Fallback.UDP443 {
		if profile, err := runtimeadapter.AltPortProfile(hub, address, privateKey); err != nil {
			b.fallbackFailed(ctx, "UDP/443", err)
		} else if _, err := b.API.SendDocument(ctx, b.Cfg.AdminID,
			runtimeadapter.RealityProfileName(deviceID), []byte(profile),
			b.text(msgFallbackUDP443Caption)); err != nil {
			b.fallbackFailed(ctx, "UDP/443", err)
		}
	}

	if !hub.Fallback.Reality.Enabled {
		return
	}
	privateRealityKey, err := b.RealityKey.PrivateKey(ctx)
	if err != nil {
		b.fallbackFailed(ctx, "TCP/443", err)
		return
	}
	publicKey, err := domain.RealityPublicKey(privateRealityKey)
	if err != nil {
		b.fallbackFailed(ctx, "TCP/443", err)
		return
	}
	// Derived from the device's public half, so a re-issued profile carries a new
	// fallback credential too. The private key is what this function was handed;
	// the hub itself only ever stores the public one.
	devicePublicKey, err := domain.PublicKeyFromPrivate(privateKey)
	if err != nil {
		b.fallbackFailed(ctx, "TCP/443", err)
		return
	}
	uuid, err := domain.RealityUserUUID(privateRealityKey, deviceID, devicePublicKey)
	if err != nil {
		b.fallbackFailed(ctx, "TCP/443", err)
		return
	}
	link, err := runtimeadapter.RealityProfileRenderer{}.Link(hub, deviceID, uuid, publicKey)
	if err != nil {
		b.fallbackFailed(ctx, "TCP/443", err)
		return
	}

	b.send(ctx, b.text(msgFallbackReality, esc(link)), nil)
	if image, err := b.QR.PNG(ctx, link); err != nil {
		b.logf("reality qr: %v", err)
	} else if _, err := b.API.SendPhoto(ctx, b.Cfg.AdminID, deviceID+"-reality.png", image,
		b.text(msgFallbackRealityCaption)); err != nil {
		b.logf("sendPhoto: %v", err)
	}
}

// --- reissue / revoke ------------------------------------------------------

func (b *Bot) reissueDevice(ctx context.Context, cb *tg.CallbackQuery, deviceID string) result {
	release, busy := b.claim(b.text(msgOperationProfileReissue, deviceID))
	if busy != nil {
		return *busy
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureConfigUnreadable), err))
	}
	var device domain.Device
	for _, candidate := range cfg.Devices {
		if candidate.ID == deviceID {
			device = candidate
		}
	}
	if device.ID == "" {
		return result{toast: b.text(msgFailureDeviceNotFound), alert: true}
	}

	privateKey, publicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureGenerateKey), err))
	}
	if err := b.Editor.SetDeviceField(deviceID, "public_key", publicKey); err != nil {
		return b.show(ctx, cb, renderFailure(b.L, b.text(msgFailureKeyWrite), err))
	}
	undoKey := func() error {
		return b.Editor.SetDeviceField(deviceID, "public_key", device.PublicKey)
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		return b.show(ctx, cb, revertEdit(b.L, b.text(msgRevertInvalidConfig), err, undoKey))
	}
	if err := b.saveProfileKey(ctx, deviceID, privateKey); err != nil {
		return b.show(ctx, cb, revertEdit(b.L, b.text(msgRevertProfileKeySaveReissue), err, undoKey))
	}
	// A re-issued device is meant to work again: lifting the revocation is part of
	// the same operation, not a separate thing to remember.
	b.self.mark(b.Now())
	if err := b.Revocations.Remove(ctx, deviceID); err != nil {
		b.send(ctx, b.text(msgRevocationRemoveFailed, esc(err.Error())), nil)
	}

	if outcome := b.sendProfile(ctx, cfg.Hub, deviceID, device.Address, privateKey); outcome != nil {
		return *outcome
	}
	view := b.afterConfigChange(b.text(msgDeviceReissued, esc(deviceID)), b.backToDevices())
	b.sendScreen(ctx, view)
	return result{toast: b.text(msgToastProfileReissued)}
}

func (b *Bot) revokeDevice(ctx context.Context, cb *tg.CallbackQuery, deviceID string) result {
	release, busy := b.claim(b.text(msgOperationDeviceRevoke, deviceID))
	if busy != nil {
		return *busy
	}
	defer release()

	b.self.mark(b.Now())
	if err := b.Revocations.Add(ctx, deviceID); err != nil {
		return result{toast: b.text(msgOperationFailed, err.Error()), alert: true}
	}
	outcome := b.show(ctx, cb, b.afterConfigChange(b.text(msgDeviceRevokedSuccess, esc(deviceID)), b.backToDevices()))
	outcome.toast = b.text(msgToastDeviceRevoked)
	return outcome
}
