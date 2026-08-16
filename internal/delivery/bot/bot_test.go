package bot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/domain"
	"vpn-hub/internal/wiring"
)

const adminID = int64(42)

// --- fakes -----------------------------------------------------------------

type sent struct {
	text   string
	markup *tg.InlineKeyboardMarkup
}

type fakeAPI struct {
	mu      sync.Mutex
	sent    []sent
	edits   []sent
	screens []sent // sent + edits in delivery order
	docs    []string
	photos  []string
	toasts  []string
	nextID  int64
	// failDocumentsAfter, when > 0, makes SendDocument fail once that many have
	// succeeded -- used to drive partial-failure flows.
	failDocumentsAfter int
}

func (f *fakeAPI) GetUpdates(context.Context, int64, int) ([]tg.Update, error) { return nil, nil }

func (f *fakeAPI) SendMessage(_ context.Context, _ int64, text string, markup *tg.InlineKeyboardMarkup) (tg.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.sent = append(f.sent, sent{text, markup})
	f.screens = append(f.screens, sent{text, markup})
	return tg.Message{ID: f.nextID, Chat: tg.Chat{ID: adminID}}, nil
}

func (f *fakeAPI) EditMessageText(_ context.Context, _, _ int64, text string, markup *tg.InlineKeyboardMarkup) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edits = append(f.edits, sent{text, markup})
	f.screens = append(f.screens, sent{text, markup})
	return nil
}

func (f *fakeAPI) AnswerCallbackQuery(_ context.Context, _, text string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.toasts = append(f.toasts, text)
	return nil
}

func (f *fakeAPI) SendDocument(_ context.Context, _ int64, filename string, _ []byte, _ string) (tg.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDocumentsAfter > 0 && len(f.docs) >= f.failDocumentsAfter {
		return tg.Message{}, fmt.Errorf("document delivery failed (test)")
	}
	f.docs = append(f.docs, filename)
	return tg.Message{}, nil
}

func (f *fakeAPI) SendPhoto(_ context.Context, _ int64, filename string, _ []byte, _ string) (tg.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.photos = append(f.photos, filename)
	return tg.Message{}, nil
}

func (f *fakeAPI) SetMyCommands(context.Context, []tg.BotCommand) error { return nil }

func (f *fakeAPI) lastScreen(t *testing.T) sent {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.screens) == 0 {
		t.Fatal("nothing was sent")
	}
	return f.screens[len(f.screens)-1]
}

type fakeJournal struct{}

func (fakeJournal) Tail(context.Context, string, int) (string, error) { return "journal line", nil }
func (fakeJournal) Follow(context.Context, []string) <-chan linux.JournalEntry {
	entries := make(chan linux.JournalEntry)
	close(entries)
	return entries
}

type fakeUnits struct{}

func (fakeUnits) Status(_ context.Context, unit string) (linux.UnitStatus, error) {
	return linux.UnitStatus{Unit: unit, Active: "active", Sub: "running"}, nil
}
func (fakeUnits) ListMatching(context.Context, string) ([]linux.UnitStatus, error) { return nil, nil }
func (fakeUnits) Restart(context.Context, string) error                            { return nil }

type fakeQR struct{}

func (fakeQR) PNG(context.Context, string) ([]byte, error) { return []byte{0x89, 'P', 'N', 'G'}, nil }

type fakePeers struct{ observation domain.IngressObservation }

func (f fakePeers) Observe(context.Context, string) (domain.IngressObservation, error) {
	return f.observation, nil
}

type fakeReconciler struct{ operations []domain.Operation }

func (f fakeReconciler) Observe(context.Context) (domain.ObservedState, error) {
	return domain.ObservedState{}, nil
}
func (f fakeReconciler) Plan(context.Context, domain.DesiredState) ([]domain.Operation, error) {
	return f.operations, nil
}
func (f fakeReconciler) Apply(context.Context, domain.DesiredState) ([]domain.Operation, error) {
	return nil, nil
}

// --- fixture ---------------------------------------------------------------

// hubFixture writes a valid single-file config with one egress tunnel and returns
// the bot wired against it and the fake API.
func hubFixture(t *testing.T) (*Bot, *fakeAPI) {
	t.Helper()
	devicePrivateKey, devicePublicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, serverPublicKey, err := domain.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`hub:
  endpoint: "vpn.example.test:51820"
  server_public_key: %q
  client_cidr: "10.80.0.0/24"
  dns_address: "10.80.0.1"
devices:
  - id: macbook
    address: "10.80.0.2/32"
    public_key: %q
    egress: direct
tunnels:
  - id: wg-nl
    type: wireguard
    role: egress
    source: {kind: config, value: "wg-nl.conf"}
`, serverPublicKey, devicePublicKey)

	configPath := filepath.Join(t.TempDir(), "hub.yaml")
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	configDir := t.TempDir()
	runtimeDir := t.TempDir()
	serverKeyPath := filepath.Join(t.TempDir(), "server.key")
	if _, err := (linux.ServerKeyFile{Path: serverKeyPath}).Create(); err != nil {
		t.Fatal(err)
	}

	api := &fakeAPI{}
	instance := &Bot{
		API:           api,
		Cfg:           Config{AdminID: adminID, Notifications: Notifications{HealthInterval: time.Minute, DriftInterval: time.Minute, SubscriptionRefresh: time.Hour}},
		ConfigPath:    configPath,
		StateDir:      stateDir,
		ConfigDir:     configDir,
		RuntimeDir:    runtimeDir,
		Service:       wiring.Service(configPath, stateDir, runtimeDir),
		Reconciler:    fakeReconciler{},
		Editor:        configadapter.Editor{Root: configPath},
		Revisions:     runtimeadapter.FileRevisionStore{StateDir: stateDir},
		Confirmations: runtimeadapter.ConfirmationStore{StateDir: stateDir},
		Revocations:   runtimeadapter.RevocationStore{StateDir: stateDir},
		ProfileKeys:   runtimeadapter.ProfileKeyStore{StateDir: stateDir},
		Settings:      runtimeadapter.BotSettingsStore{StateDir: stateDir},
		Offsets:       runtimeadapter.OffsetStore{StateDir: stateDir},
		Journal:       fakeJournal{},
		Units:         fakeUnits{},
		QR:            fakeQR{},
		Peers:         fakePeers{},
		Keys:          linux.ServerKeyFile{Path: serverKeyPath},
		Upstreams:     linux.UpstreamFile{Dir: configDir},
		Fetch: func(context.Context, string) ([]byte, error) {
			return nil, fmt.Errorf("no subscription in tests")
		},
		Parse: linux.ParseSubscription,
		Prove: func(context.Context, domain.ProxyTunnel, string) error {
			return fmt.Errorf("no canary in tests")
		},
		Host:   func() (linux.HostSnapshot, error) { return linux.HostSnapshot{}, nil },
		Uplink: func(context.Context) (string, error) { return "", fmt.Errorf("no uplink in tests") },
		Now:    func() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) },
		Out:    testWriter{t},
	}
	if err := instance.ProfileKeys.Save(context.Background(), "macbook", devicePrivateKey); err != nil {
		t.Fatal(err)
	}
	instance.init()
	return instance, api
}

// testWriter surfaces the bot's own diagnostics -- including recovered panics --
// as test log lines instead of swallowing them.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(data []byte) (int, error) {
	w.t.Logf("bot: %s", strings.TrimSpace(string(data)))
	return len(data), nil
}

func message(from int64, text string) tg.Update {
	return tg.Update{ID: 1, Message: &tg.Message{ID: 1, From: &tg.User{ID: from}, Chat: tg.Chat{ID: from}, Text: text}}
}

func tap(from int64, data string) tg.Update {
	return tg.Update{ID: 2, CallbackQuery: &tg.CallbackQuery{
		ID: "cb", From: tg.User{ID: from}, Data: data,
		Message: &tg.Message{ID: 10, Chat: tg.Chat{ID: from}},
	}}
}

// findButton returns the callback data of the first button whose label contains want.
func findButton(t *testing.T, markup *tg.InlineKeyboardMarkup, want string) string {
	t.Helper()
	if markup == nil {
		t.Fatalf("no keyboard while looking for %q", want)
	}
	for _, row := range markup.InlineKeyboard {
		for _, button := range row {
			if strings.Contains(button.Text, want) {
				return button.CallbackData
			}
		}
	}
	t.Fatalf("no button %q in %+v", want, markup.InlineKeyboard)
	return ""
}

// --- tests -----------------------------------------------------------------

// The bot must behave as if it does not exist for anyone but the admin.
func TestStrangersAreDroppedSilently(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, message(999, "/start"))
	instance.handleUpdate(ctx, tap(999, "st"))
	instance.handleUpdate(ctx, tg.Update{ID: 3}) // no sender at all

	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.sent)+len(api.edits)+len(api.toasts) != 0 {
		t.Fatalf("a stranger got an answer: %+v %+v %+v", api.sent, api.edits, api.toasts)
	}
}

func TestDevicesScreenListsDevices(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)

	instance.handleUpdate(context.Background(), message(adminID, "/devices"))

	last := api.lastScreen(t)
	if !strings.Contains(last.text, "macbook") || !strings.Contains(last.text, "direct") {
		t.Fatalf("unexpected devices screen:\n%s", last.text)
	}
	findButton(t, last.markup, "Добавить")
}

func TestSetEgressFlow(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "dev:eg:macbook"))
	choice := findButton(t, api.lastScreen(t).markup, "wg-nl")

	instance.handleUpdate(ctx, tap(adminID, choice))
	last := api.lastScreen(t)
	if !strings.Contains(last.text, "wg-nl") || !strings.Contains(last.text, "деплоя") {
		t.Fatalf("unexpected confirmation:\n%s", last.text)
	}

	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config no longer validates: %v", err)
	}
	if cfg.Devices[0].Egress != "wg-nl" {
		t.Fatalf("egress was not changed: %+v", cfg.Devices[0])
	}
}

// Disabling the tunnel a device depends on must be refused with the reason, and the
// config must be left as it was.
func TestDisableRefusedWhenADeviceDependsOnIt(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "dev:eg:macbook:wg-nl"))
	instance.handleUpdate(ctx, tap(adminID, "tun:off!:wg-nl"))

	last := api.lastScreen(t)
	if !strings.Contains(last.text, "Отменено") {
		t.Fatalf("expected the revert message, got:\n%s", last.text)
	}
	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config was left broken: %v", err)
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == "wg-nl" && !tunnel.IsEnabled() {
			t.Fatal("the tunnel was left disabled")
		}
	}
}

func TestRevokeNeedsTwoTaps(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "dev:rv:macbook"))
	if revoked, _ := instance.Revocations.Load(ctx); len(revoked) != 0 {
		t.Fatal("one tap was enough to revoke")
	}
	if !strings.Contains(api.lastScreen(t).text, "Отозвать") {
		t.Fatalf("expected a confirmation question:\n%s", api.lastScreen(t).text)
	}

	instance.handleUpdate(ctx, tap(adminID, "dev:rv!:macbook"))
	revoked, err := instance.Revocations.Load(ctx)
	if err != nil || len(revoked) != 1 || revoked[0] != "macbook" {
		t.Fatalf("revocation was not recorded: %v %v", revoked, err)
	}
}

func TestDeployArmConfirmCycle(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	// First deploy: instant, so a previous revision exists for the next one.
	instance.handleUpdate(ctx, tap(adminID, "dep"))
	first := findButton(t, api.lastScreen(t).markup, "без страховки")
	instance.handleUpdate(ctx, tap(adminID, first))
	confirmed := findButton(t, api.lastScreen(t).markup, "Да")
	instance.handleUpdate(ctx, tap(adminID, confirmed))
	if _, err := instance.Revisions.Load(ctx); err != nil {
		t.Fatalf("the first revision was not saved: %v", err)
	}

	// Change something so the next revision differs.
	instance.handleUpdate(ctx, tap(adminID, "dev:eg:macbook:wg-nl"))

	// Armed deploy: pick the deadline, pending confirmation appears, confirm clears it.
	instance.handleUpdate(ctx, tap(adminID, "dep"))
	choose := findButton(t, api.lastScreen(t).markup, "Со страховкой")
	instance.handleUpdate(ctx, tap(adminID, choose))
	armed := findButton(t, api.lastScreen(t).markup, "5 мин")
	instance.handleUpdate(ctx, tap(adminID, armed))
	if _, isArmed, _ := instance.Confirmations.Load(); !isArmed {
		t.Fatal("the deploy was not armed")
	}
	if !strings.Contains(api.lastScreen(t).text, "ждёт подтверждения") {
		t.Fatalf("expected the countdown message:\n%s", api.lastScreen(t).text)
	}

	instance.handleUpdate(ctx, tap(adminID, "dep:ok"))
	if _, isArmed, _ := instance.Confirmations.Load(); isArmed {
		t.Fatal("confirm did not clear the pending state")
	}
}

// A deploy button rendered against one revision must not apply another.
func TestDeployRefusesAStaleButton(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "dep:now!:deadbeef00000000"))
	api.mu.Lock()
	lastToast := api.toasts[len(api.toasts)-1]
	api.mu.Unlock()
	if !strings.Contains(lastToast, "Конфигурация изменилась") {
		t.Fatalf("expected the stale-preview refusal, got %q", lastToast)
	}
	if _, err := instance.Revisions.Load(ctx); err == nil {
		t.Fatal("a stale revision was deployed anyway")
	}
}

func TestBusyGateAnswersWithTheRunningOperation(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)

	release, _, ok := instance.gate.Acquire("тестовая операция")
	if !ok {
		t.Fatal("gate is unexpectedly busy")
	}
	defer release()

	instance.handleUpdate(context.Background(), tap(adminID, "dev:rv!:macbook"))
	api.mu.Lock()
	lastToast := api.toasts[len(api.toasts)-1]
	api.mu.Unlock()
	if !strings.Contains(lastToast, "тестовая операция") {
		t.Fatalf("the busy answer does not name the operation: %q", lastToast)
	}
}

func TestDeviceAddDialogDeliversProfileAndQR(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "dev:add"))
	instance.handleUpdate(ctx, message(adminID, "phone"))

	// The address step suggests the first free address.
	suggestion := findButton(t, api.lastScreen(t).markup, "Использовать")
	if !strings.Contains(suggestion, "10.80.0.3/32") {
		t.Fatalf("expected 10.80.0.3/32 to be suggested, got %q", suggestion)
	}
	instance.handleUpdate(ctx, tap(adminID, suggestion))
	egress := findButton(t, api.lastScreen(t).markup, "direct")
	instance.handleUpdate(ctx, tap(adminID, egress))

	api.mu.Lock()
	docs, photos := api.docs, api.photos
	api.mu.Unlock()
	if len(docs) != 1 || docs[0] != "phone.conf" {
		t.Fatalf("the profile file was not delivered: %v", docs)
	}
	if len(photos) != 1 {
		t.Fatalf("the QR code was not delivered: %v", photos)
	}

	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config no longer validates: %v", err)
	}
	if len(cfg.Devices) != 2 {
		t.Fatalf("the device was not added: %+v", cfg.Devices)
	}
}

// With the fallbacks on, a device gets three things instead of one: the ordinary
// profile, the same profile aimed at UDP/443, and a vless:// link with its QR. The
// point of issuing them together is that nobody has to hand-edit a port on a phone
// at the moment the ordinary path has stopped working.
func TestDeviceAddDeliversTheFallbackProfiles(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	realityKey := filepath.Join(t.TempDir(), "reality.key")
	if _, err := (linux.RealityKeyFile{Path: realityKey}).Create(); err != nil {
		t.Fatal(err)
	}
	instance.RealityKey = linux.RealityKeyFile{Path: realityKey}

	body := strings.Replace(read(t, instance.ConfigPath),
		"  dns_address: \"10.80.0.1\"\n",
		"  dns_address: \"10.80.0.1\"\n"+
			"  fallback:\n"+
			"    udp443: true\n"+
			"    reality:\n"+
			"      enabled: true\n"+
			"      server_name: \"www.example.com\"\n", 1)
	if err := os.WriteFile(instance.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	instance.handleUpdate(ctx, tap(adminID, "dev:add"))
	instance.handleUpdate(ctx, message(adminID, "phone"))
	suggestion := findButton(t, api.lastScreen(t).markup, "Использовать")
	instance.handleUpdate(ctx, tap(adminID, suggestion))
	egress := findButton(t, api.lastScreen(t).markup, "direct")
	instance.handleUpdate(ctx, tap(adminID, egress))

	api.mu.Lock()
	docs, photos := append([]string(nil), api.docs...), append([]string(nil), api.photos...)
	messages := append([]sent(nil), api.sent...)
	api.mu.Unlock()

	if len(docs) != 2 || docs[0] != "phone.conf" || docs[1] != "phone-443.conf" {
		t.Fatalf("expected the ordinary and the UDP/443 profile, got %v", docs)
	}
	if len(photos) != 2 {
		t.Fatalf("expected a QR for each way in, got %v", photos)
	}

	var link string
	for _, message := range messages {
		if strings.Contains(message.text, "vless://") {
			link = message.text
		}
	}
	if link == "" {
		t.Fatal("no vless:// link was delivered")
	}
	// The credential in the chat has to be the one the listener will admit, and the
	// listener's user list is derived from the device's public key as it appears in
	// the configuration -- so read it from there rather than trusting the renderer.
	privateKey, err := instance.RealityKey.PrivateKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var devicePublicKey string
	for _, device := range cfg.Devices {
		if device.ID == "phone" {
			devicePublicKey = device.PublicKey
		}
	}
	if devicePublicKey == "" {
		t.Fatal("the device was not added to the configuration")
	}
	uuid, err := domain.RealityUserUUID(privateKey, "phone", devicePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(link, uuid) {
		t.Errorf("the link does not carry the device's derived credential:\n%s", link)
	}
	if strings.Contains(link, privateKey) {
		t.Fatal("the hub's private key was sent to the chat")
	}
}

// A missing key must not cost the operator the ordinary profile: the fallback is
// an extra way in, and failing the whole flow over it would be a worse outcome
// than not having it.
func TestDeviceAddSurvivesAMissingRealityKey(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.RealityKey = linux.RealityKeyFile{Path: filepath.Join(t.TempDir(), "absent.key")}
	body := strings.Replace(read(t, instance.ConfigPath),
		"  dns_address: \"10.80.0.1\"\n",
		"  dns_address: \"10.80.0.1\"\n"+
			"  fallback:\n"+
			"    reality:\n"+
			"      enabled: true\n"+
			"      server_name: \"www.example.com\"\n", 1)
	if err := os.WriteFile(instance.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	instance.handleUpdate(ctx, tap(adminID, "dev:add"))
	instance.handleUpdate(ctx, message(adminID, "phone"))
	suggestion := findButton(t, api.lastScreen(t).markup, "Использовать")
	instance.handleUpdate(ctx, tap(adminID, suggestion))
	egress := findButton(t, api.lastScreen(t).markup, "direct")
	instance.handleUpdate(ctx, tap(adminID, egress))

	api.mu.Lock()
	docs, messages := append([]string(nil), api.docs...), append([]sent(nil), api.sent...)
	api.mu.Unlock()

	if len(docs) != 1 || docs[0] != "phone.conf" {
		t.Fatalf("the ordinary profile did not survive the missing key: %v", docs)
	}
	// Told in the chat, and told why: the ordinary profile arrives either way, so
	// without this the screen reads as success and the device is handed over as if
	// it could also come in on 443.
	warned := false
	for _, message := range messages {
		if strings.Contains(message.text, "Запасной вход") && strings.Contains(message.text, "keygen --reality") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the admin was not told why no fallback link arrived:\n%v", messages)
	}
}

// A hub edit that breaks validation must be reverted, and a good one must land.
func TestHubEndpointEditWithRevert(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "hub:e:endpoint"))
	instance.handleUpdate(ctx, message(adminID, "not-an-endpoint"))
	if !strings.Contains(api.lastScreen(t).text, "host:port") {
		t.Fatalf("expected the validation hint:\n%s", api.lastScreen(t).text)
	}

	instance.handleUpdate(ctx, message(adminID, "new.example.test:51821"))
	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config no longer validates: %v", err)
	}
	if cfg.Hub.Endpoint != "new.example.test:51821" {
		t.Fatalf("endpoint was not changed: %q", cfg.Hub.Endpoint)
	}
}

func TestProbeSetAndRemove(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "tun:ps:wg-nl:https"))
	// Plain http is refused by the domain's own rules: the probe exists to prove
	// the tunnel carries traffic, and it must not be spoofable in transit.
	instance.handleUpdate(ctx, message(adminID, "http://1.1.1.1/x"))
	if !strings.Contains(api.lastScreen(t).text, "Попробуйте ещё раз") {
		t.Fatalf("expected a validation refusal:\n%s", api.lastScreen(t).text)
	}

	instance.handleUpdate(ctx, message(adminID, "https://1.1.1.1/cdn-cgi/trace"))
	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config no longer validates: %v", err)
	}
	if cfg.Tunnels[0].Health.HTTPSURL != "https://1.1.1.1/cdn-cgi/trace" {
		t.Fatalf("the probe was not written: %+v", cfg.Tunnels[0].Health)
	}

	instance.handleUpdate(ctx, tap(adminID, "tun:pd:wg-nl:https"))
	cfg, _ = instance.Service.LoadAndValidate(ctx)
	if cfg.Tunnels[0].Health.HTTPSURL != "" {
		t.Fatalf("the probe was not removed: %+v", cfg.Tunnels[0].Health)
	}
}

func TestKeyRotationReissuesEveryDevice(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	before, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	instance.handleUpdate(ctx, tap(adminID, "hub:rk"))
	if !strings.Contains(api.lastScreen(t).text, "теряют связь") {
		t.Fatalf("expected the hard warning:\n%s", api.lastScreen(t).text)
	}
	instance.handleUpdate(ctx, tap(adminID, "hub:rk:go"))
	instance.wg.Wait()

	after, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config no longer validates after rotation: %v", err)
	}
	if after.Hub.ServerPublicKey == before.Hub.ServerPublicKey {
		t.Fatal("the hub key did not change")
	}
	if after.Devices[0].PublicKey == before.Devices[0].PublicKey {
		t.Fatal("the device key did not change")
	}

	api.mu.Lock()
	docs := append([]string(nil), api.docs...)
	api.mu.Unlock()
	if len(docs) != len(before.Devices) {
		t.Fatalf("expected %d profiles, got %v", len(before.Devices), docs)
	}
}

func TestCandidatePickPromotesOnlyProven(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	// Make wg-nl a subscription tunnel for this test's purposes: rewrite config.
	link := "vless://3b1c8a52-4b6e-4d8a-9f00-0123456789ab@1.2.3.4:443?encryption=none&type=tcp\n" +
		"vless://3b1c8a52-4b6e-4d8a-9f00-0123456789ab@5.6.7.8:443?encryption=none&type=tcp\n"
	instance.Fetch = func(context.Context, string) ([]byte, error) { return []byte(link), nil }
	proved := ""
	instance.Prove = func(_ context.Context, candidate domain.ProxyTunnel, _ string) error {
		proved = candidate.Server
		if candidate.Server == "1.2.3.4" {
			return fmt.Errorf("did not carry traffic")
		}
		return nil
	}
	instance.Uplink = func(context.Context) (string, error) { return "eth0", nil }

	body := strings.Replace(read(t, instance.ConfigPath),
		"    source: {kind: config, value: \"wg-nl.conf\"}",
		"    source: {kind: subscription, value: \"https://provider.example/sub\"}", 1)
	body = strings.Replace(body, "type: wireguard", "type: xray", 1)
	if err := os.WriteFile(instance.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	instance.handleUpdate(ctx, tap(adminID, "sub:cand:wg-nl"))
	instance.wg.Wait() // the candidate fetch runs in the background
	if !strings.Contains(api.lastScreen(t).text, "2 кандидата") {
		t.Fatalf("expected the candidate list:\n%s", api.lastScreen(t).text)
	}

	// The failing candidate is refused and the upstream stays absent.
	instance.handleUpdate(ctx, tap(adminID, "sub:pick:wg-nl:0"))
	instance.wg.Wait()
	if proved != "1.2.3.4" {
		t.Fatalf("the candidate was not proven: %q", proved)
	}
	if _, hasCurrent, _ := instance.Upstreams.Current("wg-nl"); hasCurrent {
		t.Fatal("a failing candidate was promoted")
	}

	// The passing one is promoted.
	instance.handleUpdate(ctx, tap(adminID, "sub:pick:wg-nl:1"))
	instance.wg.Wait()
	current, hasCurrent, _ := instance.Upstreams.Current("wg-nl")
	if !hasCurrent || current.Server != "5.6.7.8" {
		t.Fatalf("the proven candidate was not promoted: %+v %v", current, hasCurrent)
	}
}

// A manual pick goes through the real canary, whose temporary firewall table is
// hooked into forward/postrouting outside the reconciled ruleset -- if a try leaks
// it, nothing ever removes it. Stubs of Prove used to hide exactly this leak, so
// this test wires the production Canary with a recording runner instead.
func TestPickCandidateDiscardsTheCanaryFirewall(t *testing.T) {
	t.Parallel()
	instance, _ := hubFixture(t)
	ctx := context.Background()

	link := "vless://3b1c8a52-4b6e-4d8a-9f00-0123456789ab@1.2.3.4:443?encryption=none&type=tcp\n"
	instance.Fetch = func(context.Context, string) ([]byte, error) { return []byte(link), nil }
	instance.Uplink = func(context.Context) (string, error) { return "eth0", nil }

	var mu sync.Mutex
	var commands []string
	run := func(_ context.Context, name string, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		commands = append(commands, name+" "+strings.Join(args, " "))
		return "", nil
	}
	instance.Prove = func(ctx context.Context, candidate domain.ProxyTunnel, uplink string) error {
		return linux.Canary{
			Egress: linux.Egress{Run: run, SecretsDir: instance.RuntimeDir},
			Run:    run,
		}.Try(ctx, candidate, uplink)
	}

	body := strings.Replace(read(t, instance.ConfigPath),
		"    source: {kind: config, value: \"wg-nl.conf\"}",
		"    source: {kind: subscription, value: \"https://provider.example/sub\"}", 1)
	body = strings.Replace(body, "type: wireguard", "type: xray", 1)
	if err := os.WriteFile(instance.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	instance.handleUpdate(ctx, tap(adminID, "sub:cand:wg-nl"))
	instance.wg.Wait()
	instance.handleUpdate(ctx, tap(adminID, "sub:pick:wg-nl:0"))
	instance.wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	discarded := false
	for _, command := range commands {
		if strings.Contains(command, "nft delete table inet vpn_hub_canary") {
			discarded = true
			break
		}
	}
	if !discarded {
		t.Fatalf("the canary nft table was not discarded; commands:\n%s", strings.Join(commands, "\n"))
	}
	if _, err := os.Stat(filepath.Join(instance.RuntimeDir, "canary.nft")); !os.IsNotExist(err) {
		t.Errorf("canary.nft was left behind (stat: %v)", err)
	}
}

func TestAccessToggleRefusedWhenItStrandsADevice(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	// macbook uses wg-nl; allowing only some *other* device would strand it.
	instance.handleUpdate(ctx, tap(adminID, "dev:eg:macbook:wg-nl"))

	instance.handleUpdate(ctx, tap(adminID, "tun:ac:wg-nl"))
	if !strings.Contains(api.lastScreen(t).text, "разрешён <b>всем</b>") {
		t.Fatalf("expected the empty-list explanation:\n%s", api.lastScreen(t).text)
	}

	// Add a second device that will hold the only allow slot.
	instance.handleUpdate(ctx, tap(adminID, "dev:add"))
	instance.handleUpdate(ctx, message(adminID, "phone"))
	suggestion := findButton(t, api.lastScreen(t).markup, "Использовать")
	instance.handleUpdate(ctx, tap(adminID, suggestion))
	egress := findButton(t, api.lastScreen(t).markup, "direct")
	instance.handleUpdate(ctx, tap(adminID, egress))

	// Allowing only phone excludes macbook, which uses this egress → refused.
	instance.handleUpdate(ctx, tap(adminID, "tun:at:wg-nl:phone"))
	last := api.lastScreen(t)
	if !strings.Contains(last.text, "Отменено") {
		t.Fatalf("expected the revert, got:\n%s", last.text)
	}
	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config was left broken: %v", err)
	}
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == "wg-nl" && len(tunnel.AllowedDevices) != 0 {
			t.Fatalf("the exclusion was not reverted: %v", tunnel.AllowedDevices)
		}
	}

	// Allowing macbook itself is fine.
	instance.handleUpdate(ctx, tap(adminID, "tun:at:wg-nl:macbook"))
	cfg, _ = instance.Service.LoadAndValidate(ctx)
	for _, tunnel := range cfg.Tunnels {
		if tunnel.ID == "wg-nl" && (len(tunnel.AllowedDevices) != 1 || tunnel.AllowedDevices[0] != "macbook") {
			t.Fatalf("allowed_devices = %v", tunnel.AllowedDevices)
		}
	}
}

func TestAlertTogglePersists(t *testing.T) {
	t.Parallel()
	instance, _ := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "set:t:health"))
	if instance.alerts.get("health") {
		t.Fatal("the toggle did not turn the category off")
	}

	// A second bot over the same state dir starts with the saved switches.
	second := &Bot{Settings: instance.Settings}
	second.init()
	second.loadAlertSettings(ctx)
	if second.alerts.get("health") {
		t.Fatal("the saved switch did not survive a restart")
	}
	if !second.alerts.get("drift") {
		t.Fatal("an untouched category lost its default")
	}
}

// An IPv6 route survives the callback round-trip: the remove button carries a
// value with colons, which a naive split would shatter.
func TestIPv6RouteRoundTrip(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	// Add an IPv6 route to the tunnel via the dialog.
	instance.handleUpdate(ctx, tap(adminID, "tun:ra:wg-nl"))
	instance.handleUpdate(ctx, message(adminID, "fd00::/8"))
	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config no longer validates: %v", err)
	}
	if len(cfg.Tunnels[0].Routes) != 1 || cfg.Tunnels[0].Routes[0] != "fd00::/8" {
		t.Fatalf("the IPv6 route was not added: %v", cfg.Tunnels[0].Routes)
	}

	// The card offers a remove button whose callback carries the IPv6 value.
	instance.handleUpdate(ctx, tap(adminID, "tun:c:wg-nl"))
	remove := findButton(t, api.lastScreen(t).markup, "fd00::/8")
	if !strings.HasSuffix(remove, "fd00::/8") {
		t.Fatalf("remove callback lost the colons: %q", remove)
	}
	instance.handleUpdate(ctx, tap(adminID, remove))

	cfg, _ = instance.Service.LoadAndValidate(ctx)
	if len(cfg.Tunnels[0].Routes) != 0 {
		t.Fatalf("the IPv6 route was not removed: %v", cfg.Tunnels[0].Routes)
	}
}

// A restart resumes past the last processed update instead of replaying it -- the
// safety behind not re-running a confirmed key rotation.
func TestOffsetResumesPastProcessedUpdates(t *testing.T) {
	t.Parallel()
	store := runtimeadapter.OffsetStore{StateDir: t.TempDir()}
	if err := store.Save(41); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || got != 41 {
		t.Fatalf("offset did not persist: %d %v", got, err)
	}
}

// Key rotation that fails partway must name which devices were re-issued and which
// still need it by hand, and must not lose the profiles it already delivered.
func TestKeyRotationPartialFailureIsHonest(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	// Add a second device so the rotation has more than one to walk.
	instance.handleUpdate(ctx, tap(adminID, "dev:add"))
	instance.handleUpdate(ctx, message(adminID, "phone"))
	suggestion := findButton(t, api.lastScreen(t).markup, "Использовать")
	instance.handleUpdate(ctx, tap(adminID, suggestion))
	egress := findButton(t, api.lastScreen(t).markup, "direct")
	instance.handleUpdate(ctx, tap(adminID, egress))

	// Fail every SendDocument after the first, so exactly one profile is delivered.
	api.failDocumentsAfter = 1

	instance.handleUpdate(ctx, tap(adminID, "hub:rk"))
	instance.handleUpdate(ctx, tap(adminID, "hub:rk:go"))
	instance.wg.Wait()

	last := api.lastScreen(t)
	if !strings.Contains(last.text, "прервана") {
		t.Fatalf("expected an interrupted-rotation message:\n%s", last.text)
	}
	if !strings.Contains(last.text, "перевыпуска вручную") {
		t.Fatalf("the message must name devices needing manual re-issue:\n%s", last.text)
	}
}

func TestAWGParameterAddAndRemove(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "hub:aa"))
	// An unknown parameter is refused.
	instance.handleUpdate(ctx, message(adminID, "Nope 5"))
	if !strings.Contains(api.lastScreen(t).text, "неизвестен") {
		t.Fatalf("expected an unknown-parameter refusal:\n%s", api.lastScreen(t).text)
	}
	// A known one with a numeric value lands.
	instance.handleUpdate(ctx, message(adminID, "Jc 5"))
	cfg, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatalf("config no longer validates: %v", err)
	}
	if cfg.Hub.AWGInterface["jc"] != "5" {
		t.Fatalf("the parameter was not written: %v", cfg.Hub.AWGInterface)
	}

	instance.handleUpdate(ctx, tap(adminID, "hub:ad:jc"))
	cfg, _ = instance.Service.LoadAndValidate(ctx)
	if _, exists := cfg.Hub.AWGInterface["jc"]; exists {
		t.Fatalf("the parameter was not removed: %v", cfg.Hub.AWGInterface)
	}
}

// Re-issuing a revoked device lifts the revocation as part of the same action.
func TestReissueLiftsRevocation(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "dev:rv!:macbook"))
	if revoked, _ := instance.Revocations.Load(ctx); len(revoked) != 1 {
		t.Fatal("the device was not revoked")
	}

	before, _ := instance.Service.LoadAndValidate(ctx)
	instance.handleUpdate(ctx, tap(adminID, "dev:re!:macbook"))

	revoked, _ := instance.Revocations.Load(ctx)
	if len(revoked) != 0 {
		t.Fatalf("re-issue did not lift the revocation: %v", revoked)
	}
	after, _ := instance.Service.LoadAndValidate(ctx)
	if after.Devices[0].PublicKey == before.Devices[0].PublicKey {
		t.Fatal("re-issue did not change the device key")
	}
	api.mu.Lock()
	docs := len(api.docs)
	api.mu.Unlock()
	if docs != 1 {
		t.Fatalf("expected a re-issued profile document, got %d", docs)
	}
}

func TestSendCurrentProfile(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	before, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	instance.handleUpdate(ctx, tap(adminID, "dev:pr:macbook"))

	after, err := instance.Service.LoadAndValidate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Devices[0].PublicKey != before.Devices[0].PublicKey {
		t.Fatal("resending a profile must not rotate its key")
	}
	api.mu.Lock()
	docs := len(api.docs)
	filename := ""
	if docs > 0 {
		filename = api.docs[0]
	}
	api.mu.Unlock()
	if docs != 1 || filename != "macbook.conf" {
		t.Fatalf("expected current profile document, got docs=%d filename=%q", docs, filename)
	}
}

func TestLastKnownGoodRestore(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	// Turn wg-nl into a subscription tunnel and seed an upstream + last-known-good.
	body := strings.Replace(read(t, instance.ConfigPath),
		"    source: {kind: config, value: \"wg-nl.conf\"}",
		"    source: {kind: subscription, value: \"https://provider.example/sub\"}", 1)
	body = strings.Replace(body, "type: wireguard", "type: xray", 1)
	if err := os.WriteFile(instance.ConfigPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	tunnel := domain.Tunnel{ID: "wg-nl", Source: domain.TunnelSource{Kind: domain.SourceSubscription}}
	proxy := func(server string) domain.ProxyTunnel {
		return domain.ProxyTunnel{Protocol: "vless", Server: server, Port: 443, UUID: "3b1c8a52-4b6e-4d8a-9f00-0123456789ab"}
	}
	if err := instance.Upstreams.Write(ctx, tunnel, proxy("1.1.1.1")); err != nil {
		t.Fatal(err)
	}
	if err := instance.Upstreams.Write(ctx, tunnel, proxy("2.2.2.2")); err != nil {
		t.Fatal(err)
	}

	instance.handleUpdate(ctx, tap(adminID, "sub:lkg!:wg-nl"))
	if !strings.Contains(api.lastScreen(t).text, "1.1.1.1") {
		t.Fatalf("expected the previous upstream restored:\n%s", api.lastScreen(t).text)
	}
	current, hasCurrent, _ := instance.Upstreams.Current("wg-nl")
	if !hasCurrent || current.Server != "1.1.1.1" {
		t.Fatalf("the active upstream was not restored: %+v", current)
	}
}

func TestDeployRollback(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	// Deploy once so there is a revision, then arm a second so a rollback has a
	// target.
	instance.handleUpdate(ctx, tap(adminID, "dep"))
	first := findButton(t, api.lastScreen(t).markup, "без страховки")
	instance.handleUpdate(ctx, tap(adminID, first))
	confirmed := findButton(t, api.lastScreen(t).markup, "Да")
	instance.handleUpdate(ctx, tap(adminID, confirmed))

	instance.handleUpdate(ctx, tap(adminID, "dev:eg:macbook:wg-nl"))
	instance.handleUpdate(ctx, tap(adminID, "dep"))
	choose := findButton(t, api.lastScreen(t).markup, "Со страховкой")
	instance.handleUpdate(ctx, tap(adminID, choose))
	armed := findButton(t, api.lastScreen(t).markup, "5 мин")
	instance.handleUpdate(ctx, tap(adminID, armed))

	instance.handleUpdate(ctx, tap(adminID, "dep:rb!"))
	if _, isArmed, _ := instance.Confirmations.Load(); isArmed {
		t.Fatal("rollback did not clear the pending state")
	}
	if !strings.Contains(api.lastScreen(t).text, "Восстановлена") {
		t.Fatalf("expected a rollback confirmation:\n%s", api.lastScreen(t).text)
	}
}

func TestExportConfigSendsDocuments(t *testing.T) {
	t.Parallel()
	instance, api := hubFixture(t)
	ctx := context.Background()

	instance.handleUpdate(ctx, tap(adminID, "hub:dl!"))
	instance.wg.Wait()

	api.mu.Lock()
	docs := append([]string(nil), api.docs...)
	api.mu.Unlock()
	if len(docs) != 1 || docs[0] != "hub.yaml" {
		t.Fatalf("expected the config file to be sent, got %v", docs)
	}
}

func TestClampToast(t *testing.T) {
	t.Parallel()
	short := "коротко"
	if clampToast(short) != short {
		t.Fatal("a short toast must pass through unchanged")
	}
	long := strings.Repeat("ошибка ", 100)
	clamped := clampToast(long)
	if n := len([]rune(clamped)); n > 190 {
		t.Fatalf("clamped toast is %d runes, over 190", n)
	}
	if !strings.HasSuffix(clamped, "…") {
		t.Fatal("a clamped toast must end with an ellipsis")
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
