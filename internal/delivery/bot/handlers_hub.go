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

// hubFieldTitles names the editable hub scalars in the operator's language.
var hubFieldTitles = map[string]string{
	"endpoint":    "endpoint (host:port)",
	"dns_address": "DNS-адрес",
	"client_cidr": "клиентская сеть (CIDR)",
}

func (b *Bot) buildHub(ctx context.Context) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	return scr(renderHub(cfg.Hub))
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
			return result{toast: "Не понимаю это поле"}
		}
		field := args[0]
		b.dialogs.start(dialogHubEdit, map[string]string{"field": field})
		return b.show(ctx, cb, screen{
			text: fmt.Sprintf("✏️ Введите новое значение для <b>%s</b>.\n⚠️ Смена ломает выданные профили: после неё устройства придётся перевыпустить.",
				esc(hubFieldTitles[field])),
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "hub:x")}),
		})
	case "aa":
		b.dialogs.start(dialogAWGSet, nil)
		return b.show(ctx, cb, screen{
			text: "➕ Введите AmneziaWG-параметр в виде <code>имя значение</code>, например <code>Jc 5</code>.\n" +
				"Допустимы известные параметры (Jc, Jmin, Jmax, S1, S2, H1–H4) с числовым значением.",
			markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "hub:x")}),
		})
	case "ad":
		if len(args) < 1 {
			return result{toast: "Не указан параметр"}
		}
		return b.removeAWGParameter(ctx, cb, args[0])
	case "rk":
		return b.routeKeyRotation(ctx, cb, args)
	case "dl":
		return b.show(ctx, cb, scr(renderConfirm(
			"Выгрузить YAML-конфигурацию в чат? Файлы содержат подписочные URL с токенами — это секреты. Файлы провайдеров и ключи не выгружаются.",
			"hub:dl!", "hub")))
	case "dl!":
		return b.exportConfig(ctx)
	default:
		return result{toast: "Не понимаю эту кнопку"}
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
				b.send(ctx, "⚠️ <code>"+esc(path)+"</code> не прочитался: <code>"+esc(err.Error())+"</code>", nil)
				continue
			}
			if _, err := b.API.SendDocument(ctx, b.Cfg.AdminID, filepath.Base(path), content,
				"📦 <code>"+esc(path)+"</code>"); err != nil {
				b.send(ctx, "⚠️ <code>"+esc(path)+"</code> не отправился: <code>"+esc(err.Error())+"</code>", nil)
				continue
			}
			sent++
		}
		b.send(ctx, fmt.Sprintf("📦 Выгружено файлов: %d из %d. Удалите их из чата, когда заберёте.", sent, len(paths)),
			keyboard([]tg.InlineKeyboardButton{btn("⚙️ Хаб", "hub")}))
	})
	return result{toast: "Выгружаю…"}
}

// validateHubField pre-checks a value so the dialog can complain precisely; the
// authoritative check is still LoadAndValidate after the write.
func validateHubField(field, value string) error {
	switch field {
	case "endpoint":
		host, port, err := net.SplitHostPort(value)
		if err != nil || host == "" {
			return fmt.Errorf("endpoint должен быть host:port, например vpn.example.com:51820")
		}
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return fmt.Errorf("порт %q не похож на порт", port)
		}
	case "dns_address":
		if _, err := netip.ParseAddr(value); err != nil {
			return fmt.Errorf("%q не IP-адрес", value)
		}
	case "client_cidr":
		if _, err := netip.ParsePrefix(value); err != nil {
			return fmt.Errorf("%q не CIDR, например 10.80.0.0/24", value)
		}
	}
	return nil
}

func (b *Bot) handleHubEditInput(ctx context.Context, dialog *dialog, text string) {
	field := dialog.data["field"]
	if err := validateHubField(field, text); err != nil {
		b.send(ctx, "⚠️ "+esc(err.Error())+". Попробуйте ещё раз или /cancel.", nil)
		return
	}
	b.dialogs.clear()

	release, busyWith, ok := b.gate.Acquire("правка хаба: " + field)
	if !ok {
		b.send(ctx, "⏳ Занято: "+esc(busyWith)+". Повторите позже.", nil)
		return
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.sendScreen(ctx, renderFailure("конфигурация не читается", err))
		return
	}
	previous := map[string]string{
		"endpoint":    cfg.Hub.Endpoint,
		"dns_address": cfg.Hub.DNSAddress,
		"client_cidr": cfg.Hub.ClientCIDR,
	}[field]

	if err := b.Editor.SetHubField(field, text); err != nil {
		b.sendScreen(ctx, renderFailure("значение не записалось", err))
		return
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		_ = b.Editor.SetHubField(field, previous)
		b.sendScreen(ctx, renderFailure("отменено: конфигурация не проходит проверку", err))
		return
	}
	b.sendScreen(ctx, screen{
		text: fmt.Sprintf("✅ <b>%s</b>: <code>%s</code> → <code>%s</code>\n\n"+
			"Профили устройств теперь указывают на старое значение — перевыпустите их и задеплойте.",
			esc(hubFieldTitles[field]), esc(previous), esc(text)),
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("📱 Устройства", "dev"), btn("🚀 Деплой", "dep")},
			[]tg.InlineKeyboardButton{btn("⚙️ Хаб", "hub")},
		),
	})
}

func (b *Bot) handleAWGSetInput(ctx context.Context, _ *dialog, text string) {
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '=' })
	if len(fields) != 2 {
		b.send(ctx, "⚠️ Нужно два слова: <code>имя значение</code>. Попробуйте ещё раз или /cancel.", nil)
		return
	}
	name, value := fields[0], fields[1]
	canonical, known := domain.CanonicalAWGParameter(name)
	if !known {
		b.send(ctx, "⚠️ Параметр <code>"+esc(name)+"</code> неизвестен. Допустимы Jc, Jmin, Jmax, S1, S2, H1–H4. Ещё раз или /cancel.", nil)
		return
	}
	if _, err := strconv.Atoi(value); err != nil {
		b.send(ctx, "⚠️ Значение должно быть числом. Ещё раз или /cancel.", nil)
		return
	}
	b.dialogs.clear()

	release, busyWith, ok := b.gate.Acquire("правка AWG-параметра " + canonical)
	if !ok {
		b.send(ctx, "⏳ Занято: "+esc(busyWith)+". Повторите позже.", nil)
		return
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		b.sendScreen(ctx, renderFailure("конфигурация не читается", err))
		return
	}
	// The config decodes keys lower-cased; write the same shape it already holds.
	key := strings.ToLower(canonical)
	previous, existed := cfg.Hub.AWGInterface[key]

	if err := b.Editor.SetHubMapField("awg_interface", key, value); err != nil {
		b.sendScreen(ctx, renderFailure("параметр не записался", err))
		return
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		if existed {
			_ = b.Editor.SetHubMapField("awg_interface", key, previous)
		} else {
			_ = b.Editor.RemoveHubMapField("awg_interface", key)
		}
		b.sendScreen(ctx, renderFailure("отменено: конфигурация не проходит проверку", err))
		return
	}
	b.sendScreen(ctx, b.afterHubChange(fmt.Sprintf("✅ <code>%s = %s</code> записан.", esc(canonical), esc(value))))
}

// afterHubChange reminds that obfuscation parameters live in client profiles too.
func (b *Bot) afterHubChange(text string) screen {
	return screen{
		text: text + "\n\nAWG-параметры входят в профили устройств: перевыпустите их и задеплойте.",
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("📱 Устройства", "dev"), btn("🚀 Деплой", "dep")},
			[]tg.InlineKeyboardButton{btn("⚙️ Хаб", "hub")},
		),
	}
}

func (b *Bot) removeAWGParameter(ctx context.Context, cb *tg.CallbackQuery, key string) result {
	release, busyWith, ok := b.gate.Acquire("удаление AWG-параметра " + key)
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return b.show(ctx, cb, renderFailure("конфигурация не читается", err))
	}
	previous, existed := cfg.Hub.AWGInterface[key]
	if !existed {
		return result{toast: "Такого параметра уже нет", alert: true}
	}

	if err := b.Editor.RemoveHubMapField("awg_interface", key); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		_ = b.Editor.SetHubMapField("awg_interface", key, previous)
		return b.show(ctx, cb, renderFailure("отменено: конфигурация не проходит проверку", err))
	}
	outcome := b.show(ctx, cb, b.buildHub(ctx))
	name, _ := domain.CanonicalAWGParameter(key)
	outcome.toast = "Удалён параметр " + name
	return outcome
}

// --- Hub key rotation ------------------------------------------------------

func (b *Bot) routeKeyRotation(ctx context.Context, cb *tg.CallbackQuery, args []string) result {
	if len(args) == 0 {
		return b.show(ctx, cb, screen{
			text: "🔑 <b>Ротация ключа хаба</b>\n\n" +
				"Будет сгенерирован новый серверный ключ, перевыпущены профили <b>всех</b> устройств (файлы и QR придут в этот чат), обновлена конфигурация.\n\n" +
				"⚠️ <b>Все устройства теряют связь</b>, пока на них не установят новые профили и не пройдёт деплой.\n" +
				"⚠️ Откат ревизии <b>не вернёт</b> старый ключ — он останется в <code>server.key.previous</code> на хабе.\n" +
				"⚠️ Не запускайте это с устройства, чей интернет идёт через этот хаб: связь оборвётся на середине.",
			markup: keyboard(
				[]tg.InlineKeyboardButton{btn("Да, ротировать", "hub:rk:go"), btn("Нет", "hub")},
			),
		})
	}
	if args[0] != "go" {
		return result{toast: "Не понимаю эту кнопку"}
	}

	release, busyWith, ok := b.gate.Acquire("ротация ключа хаба")
	if !ok {
		return busyResult(busyWith)
	}

	progress, err := b.API.SendMessage(ctx, b.Cfg.AdminID, "🔑 Ротация: генерирую новый ключ…", nil)
	if err != nil {
		release()
		return result{toast: "Не удалось начать: " + err.Error(), alert: true}
	}

	b.spawn("key-rotation", func() {
		defer release()
		b.rotateHubKey(ctx, progress.Chat.ID, progress.ID)
	})
	return result{toast: "Начал"}
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
		edit("⛔ Ротация не начата: конфигурация не читается.\n<code>" + esc(err.Error()) + "</code>")
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
		fmt.Fprintf(&b2, "⛔ Ротация прервана на шаге «%s»:\n<code>%s</code>\n\n", esc(stage), esc(cause.Error()))
		b2.WriteString("Ключ хаба уже заменён — старые профили <b>всех</b> устройств больше не работают.\n")
		if len(delivered) > 0 {
			fmt.Fprintf(&b2, "✅ Новые профили доставлены: <code>%s</code>\n", esc(strings.Join(delivered, ", ")))
		}
		pending := subtract(allDevices, delivered)
		if len(pending) > 0 {
			fmt.Fprintf(&b2, "⚠️ Требуют перевыпуска вручную (📱 Устройства → Перевыпустить): <code>%s</code>\n", esc(strings.Join(pending, ", ")))
		}
		b2.WriteString("\nСтарый ключ сохранён в <code>server.key.previous</code>.")
		b.sendScreen(ctx, screen{text: b2.String(), markup: keyboard(
			[]tg.InlineKeyboardButton{btn("📱 Устройства", "dev"), btn("📊 Статус", "st")},
		)})
	}

	publicKey, err := b.Keys.Rotate()
	if err != nil {
		edit("⛔ Ротация не начата: новый ключ не сгенерирован.\n<code>" + esc(err.Error()) + "</code>")
		return
	}
	edit("🔑 Ключ заменён. Обновляю конфигурацию…")

	if err := b.Editor.SetHubField("server_public_key", publicKey); err != nil {
		// The one irrecoverable-by-bot spot: the on-disk key is new but the config
		// still names the old public key, so nothing matches until they do.
		edit("⛔ Ключ заменён на диске, но не записан в конфиг:\n<code>" + esc(err.Error()) + "</code>\n\n" +
			"Конфиг и server.key рассинхронизированы. Восстановите прежний ключ на хосте:\n" +
			"<code>mv /etc/vpn-hub/server.key.previous /etc/vpn-hub/server.key</code>")
		return
	}

	// Reload so profiles carry the new hub public key (it is the [Peer] key in
	// every client profile). Device keys are still the old values here, which
	// validation accepts -- it does not cross-check them against the hub key.
	withNewKey, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		fail("проверка конфигурации после смены ключа хаба", err, nil)
		return
	}

	// Each device's key is written and its profile delivered in the same step, so
	// a private key never lives only in memory across a later failure.
	var delivered []string
	for _, device := range cfg.Devices {
		privateKey, devicePublic, err := domain.GenerateX25519KeyPair()
		if err != nil {
			fail("генерация ключа устройства "+device.ID, err, delivered)
			return
		}
		if err := b.Editor.SetDeviceField(device.ID, "public_key", devicePublic); err != nil {
			fail("запись ключа устройства "+device.ID, err, delivered)
			return
		}
		if outcome := b.sendProfile(ctx, withNewKey.Hub, device.ID, device.Address, privateKey); outcome != nil {
			fail("доставка профиля "+device.ID, fmt.Errorf("сообщение не отправилось"), delivered)
			return
		}
		delivered = append(delivered, device.ID)
	}

	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		fail("итоговая проверка конфигурации", err, delivered)
		return
	}

	b.sendScreen(ctx, screen{
		text: "🔑 <b>Ротация завершена.</b>\n\n" +
			"Профили всех устройств выше — установите их и удалите из чата.\n" +
			"Остался деплой. Страховка тут не поможет: откат ревизии не вернёт старый ключ, поэтому деплойте сразу.",
		markup: keyboard(
			[]tg.InlineKeyboardButton{btn("🚀 К деплою", "dep")},
			backRow,
		),
	})
	edit("🔑 Ротация выполнена, детали ниже.")
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

func (b *Bot) buildProbes(ctx context.Context, tunnelID string) screen {
	cfg, err := b.Service.LoadAndValidate(ctx)
	if err != nil {
		return renderFailure("конфигурация не читается", err)
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == tunnelID {
			return scr(renderProbes(tunnelID, tunnel.Health))
		}
	}
	return renderFailure("туннель не найден", fmt.Errorf("нет туннеля %q", tunnelID))
}

func (b *Bot) startProbeDialog(ctx context.Context, cb *tg.CallbackQuery, tunnelID, kindKey string) result {
	_, title, example, ok := probeKind(kindKey)
	if !ok {
		return result{toast: "Не понимаю вид пробы"}
	}
	b.dialogs.start(dialogProbeSet, map[string]string{"tunnel": tunnelID, "kind": kindKey})
	return b.show(ctx, cb, screen{
		text: fmt.Sprintf("🩺 %s-проба для <b>%s</b>: пришлите значение, например <code>%s</code>.",
			esc(title), esc(tunnelID), esc(example)),
		markup: keyboard([]tg.InlineKeyboardButton{btn("✖️ Отмена", "tun:pr:"+tunnelID)}),
	})
}

func (b *Bot) handleProbeSetInput(ctx context.Context, dialog *dialog, text string) {
	tunnelID, kindKey := dialog.data["tunnel"], dialog.data["kind"]
	field, title, _, ok := probeKind(kindKey)
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
		b.send(ctx, "⚠️ "+esc(err.Error())+". Попробуйте ещё раз или /cancel.", nil)
		return
	}
	b.dialogs.clear()

	release, busyWith, ok := b.gate.Acquire("проба " + title + " у " + tunnelID)
	if !ok {
		b.send(ctx, "⏳ Занято: "+esc(busyWith)+". Повторите позже.", nil)
		return
	}
	defer release()

	if err := b.Editor.SetTunnelMapField(tunnelID, "health", field, text); err != nil {
		b.sendScreen(ctx, renderFailure("проба не записалась", err))
		return
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		_ = b.Editor.RemoveTunnelMapField(tunnelID, "health", field)
		b.sendScreen(ctx, renderFailure("отменено: конфигурация не проходит проверку", err))
		return
	}
	b.sendScreen(ctx, b.buildProbes(ctx, tunnelID))
}

func (b *Bot) removeProbe(ctx context.Context, cb *tg.CallbackQuery, tunnelID, kindKey string) result {
	field, title, _, ok := probeKind(kindKey)
	if !ok {
		return result{toast: "Не понимаю вид пробы"}
	}
	release, busyWith, ok := b.gate.Acquire("удаление пробы " + title + " у " + tunnelID)
	if !ok {
		return busyResult(busyWith)
	}
	defer release()

	if err := b.Editor.RemoveTunnelMapField(tunnelID, "health", field); err != nil {
		return result{toast: err.Error(), alert: true}
	}
	if _, err := b.Service.LoadAndValidate(ctx); err != nil {
		return b.show(ctx, cb, renderFailure("проба удалена, но конфигурация перестала проходить проверку", err))
	}
	outcome := b.show(ctx, cb, b.buildProbes(ctx, tunnelID))
	outcome.toast = "Удалена " + title + "-проба"
	return outcome
}
