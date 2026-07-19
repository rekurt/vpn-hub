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
	_, devicePublicKey, err := domain.GenerateX25519KeyPair()
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

	api := &fakeAPI{}
	instance := &Bot{
		API:           api,
		Cfg:           Config{AdminID: adminID, Notifications: Notifications{HealthInterval: time.Minute, DriftInterval: time.Minute, SubscriptionRefresh: time.Hour}},
		ConfigPath:    configPath,
		StateDir:      stateDir,
		ConfigDir:     t.TempDir(),
		RuntimeDir:    t.TempDir(),
		Service:       wiring.Service(configPath, stateDir),
		Reconciler:    fakeReconciler{},
		Editor:        configadapter.Editor{Root: configPath},
		Revisions:     runtimeadapter.FileRevisionStore{StateDir: stateDir},
		Confirmations: runtimeadapter.ConfirmationStore{StateDir: stateDir},
		Revocations:   runtimeadapter.RevocationStore{StateDir: stateDir},
		Settings:      runtimeadapter.BotSettingsStore{StateDir: stateDir},
		Journal:       fakeJournal{},
		Units:         fakeUnits{},
		QR:            fakeQR{},
		Host:          func() (linux.HostSnapshot, error) { return linux.HostSnapshot{}, nil },
		Uplink:        func(context.Context) (string, error) { return "", fmt.Errorf("no uplink in tests") },
		Now:           func() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) },
		Out:           testWriter{t},
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

	// Armed deploy: pending confirmation appears, confirm clears it.
	instance.handleUpdate(ctx, tap(adminID, "dep"))
	armed := findButton(t, api.lastScreen(t).markup, "страховка 5 мин")
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
