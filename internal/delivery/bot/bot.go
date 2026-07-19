package bot

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	configadapter "vpn-hub/internal/adapters/config"
	"vpn-hub/internal/adapters/linux"
	runtimeadapter "vpn-hub/internal/adapters/runtime"
	tg "vpn-hub/internal/adapters/telegram"
	"vpn-hub/internal/application"
	"vpn-hub/internal/domain"
	"vpn-hub/internal/ports"
	"vpn-hub/internal/wiring"
)

// API is the slice of the Telegram client the bot drives; tests substitute a fake.
type API interface {
	GetUpdates(ctx context.Context, offset int64, timeout int) ([]tg.Update, error)
	SendMessage(ctx context.Context, chatID int64, text string, keyboard *tg.InlineKeyboardMarkup) (tg.Message, error)
	EditMessageText(ctx context.Context, chatID, messageID int64, text string, keyboard *tg.InlineKeyboardMarkup) error
	AnswerCallbackQuery(ctx context.Context, callbackID, text string, showAlert bool) error
	SendDocument(ctx context.Context, chatID int64, filename string, content []byte, caption string) (tg.Message, error)
	SendPhoto(ctx context.Context, chatID int64, filename string, content []byte, caption string) (tg.Message, error)
	SetMyCommands(ctx context.Context, commands []tg.BotCommand) error
}

type journalReader interface {
	Tail(ctx context.Context, unit string, lines int) (string, error)
	Follow(ctx context.Context, units []string) <-chan linux.JournalEntry
}

type unitManager interface {
	Status(ctx context.Context, unit string) (linux.UnitStatus, error)
	ListMatching(ctx context.Context, pattern string) ([]linux.UnitStatus, error)
	Restart(ctx context.Context, unit string) error
}

type qrEncoder interface {
	PNG(ctx context.Context, text string) ([]byte, error)
}

// settingsStore keeps what the admin tuned at runtime across bot restarts -- and
// the bot restarts on every deploy.
type settingsStore interface {
	Load(ctx context.Context) (runtimeadapter.BotSettings, error)
	Save(ctx context.Context, settings runtimeadapter.BotSettings) error
}

// refreshFunc proves subscription candidates and promotes one, reporting progress
// as it goes so a minutes-long canary run does not look hung in the chat.
type refreshFunc func(ctx context.Context, tunnel domain.Tunnel, progress func(tried, total int, rejected []string)) (domain.ProxyTunnel, []string, error)

// Bot is the Telegram delivery. It is the operator's seat, not the reconciler:
// like hubctl it edits configuration and writes state, and the agent converges the
// host on its own schedule.
type Bot struct {
	API API
	Cfg Config
	// Out receives the bot's own diagnostics, which land in its journal.
	Out io.Writer

	ConfigPath string
	StateDir   string
	ConfigDir  string
	RuntimeDir string

	Service       application.Service
	Reconciler    ports.Reconciler
	Editor        configadapter.Editor
	Revisions     runtimeadapter.FileRevisionStore
	Confirmations runtimeadapter.ConfirmationStore
	Revocations   runtimeadapter.RevocationStore
	Profiles      runtimeadapter.AmneziaProfileRenderer
	Settings      settingsStore

	Journal journalReader
	Units   unitManager
	QR      qrEncoder
	Host    func() (linux.HostSnapshot, error)
	Uplink  func(ctx context.Context) (string, error)
	Refresh refreshFunc
	Now     func() time.Time

	gate    opsGate
	dialogs dialogs
	alerts  *alertSwitches
	health  *healthBoard
	self    *selfMarks
	deploy  *deployWatch
	events  chan event
	wg      sync.WaitGroup
}

// New wires the production bot. Fields stay exported so tests can build a Bot by
// hand with fakes instead.
func New(cfg Config, client *tg.Client, configPath, stateDir, configDir, runtimeDir, serverKey string, out io.Writer) *Bot {
	b := &Bot{
		API:        client,
		Cfg:        cfg,
		Out:        out,
		ConfigPath: configPath,
		StateDir:   stateDir,
		ConfigDir:  configDir,
		RuntimeDir: runtimeDir,

		Service:       wiring.Service(configPath, stateDir),
		Reconciler:    wiring.Reconciler(serverKey, runtimeDir, configDir),
		Editor:        configadapter.Editor{Root: configPath},
		Revisions:     runtimeadapter.FileRevisionStore{StateDir: stateDir},
		Confirmations: runtimeadapter.ConfirmationStore{StateDir: stateDir},
		Revocations:   runtimeadapter.RevocationStore{StateDir: stateDir},
		Settings:      runtimeadapter.BotSettingsStore{StateDir: stateDir},

		Journal: linux.Journal{},
		Units:   linux.Systemctl{},
		QR:      linux.QREncoder{},
		Host:    linux.HostInfo{}.Snapshot,
		Uplink:  linux.NetConf{}.UplinkInterface,
		Now:     time.Now,
	}
	b.Refresh = b.canaryRefresh
	b.init()
	return b
}

// init sets up the internal state New and the tests both need.
func (b *Bot) init() {
	if b.events == nil {
		b.events = make(chan event, 128)
	}
	if b.alerts == nil {
		b.alerts = newAlertSwitches()
	}
	if b.health == nil {
		b.health = &healthBoard{}
	}
	if b.self == nil {
		b.self = &selfMarks{}
	}
	if b.deploy == nil {
		b.deploy = &deployWatch{}
	}
	if b.Now == nil {
		b.Now = time.Now
	}
	if b.Out == nil {
		b.Out = io.Discard
	}
}

func (b *Bot) logf(format string, args ...any) {
	_, _ = fmt.Fprintf(b.Out, format+"\n", args...)
}

// spawn runs a worker the bot waits for on shutdown.
func (b *Bot) spawn(name string, worker func()) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() {
			if reason := recover(); reason != nil {
				b.logf("panic in %s: %v", name, reason)
			}
		}()
		worker()
	}()
}

var botCommands = []tg.BotCommand{
	{Command: "start", Description: "Главное меню"},
	{Command: "status", Description: "Статус хаба"},
	{Command: "devices", Description: "Устройства"},
	{Command: "tunnels", Description: "Туннели"},
	{Command: "deploy", Description: "Деплой конфигурации"},
	{Command: "subs", Description: "Подписки"},
	{Command: "routes", Description: "Маршруты"},
	{Command: "logs", Description: "Логи"},
	{Command: "host", Description: "Хост и юниты"},
	{Command: "settings", Description: "Уведомления"},
	{Command: "cancel", Description: "Прервать диалог"},
}

// Run drives the update loop until the context ends. Everything the bot does on
// its own -- watching, probing, scheduled refreshes -- starts here too.
func (b *Bot) Run(ctx context.Context) error {
	b.init()
	b.loadAlertSettings(ctx)
	if err := b.API.SetMyCommands(ctx, botCommands); err != nil {
		b.logf("setMyCommands: %v", err)
	}

	b.spawn("notifier", func() { b.notifier(ctx) })
	b.spawn("journal-watcher", func() { b.watchJournal(ctx) })
	b.spawn("file-watcher", func() { b.watchStateFiles(ctx) })
	b.spawn("health-prober", func() { b.probeHealth(ctx) })
	b.spawn("drift-watcher", func() { b.watchDrift(ctx) })
	b.spawn("subscription-scheduler", func() { b.scheduleRefreshes(ctx) })

	menu := scr(renderMain())
	if _, err := b.API.SendMessage(ctx, b.Cfg.AdminID, "🤖 Бот запущен.\n\n"+menu.text, menu.markup); err != nil {
		b.logf("startup message: %v", err)
	}

	var offset int64
	for ctx.Err() == nil {
		updates, err := b.API.GetUpdates(ctx, offset, 25)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			b.logf("getUpdates: %v", err)
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			continue
		}
		for _, update := range updates {
			offset = update.ID + 1
			b.handleUpdate(ctx, update)
		}
	}
	b.wg.Wait()
	return ctx.Err()
}

// handleUpdate authorizes and dispatches one update. Strangers are dropped before
// any parsing: this bot exists for exactly one person, and for everyone else it
// must behave like it does not exist.
func (b *Bot) handleUpdate(ctx context.Context, update tg.Update) {
	defer func() {
		if reason := recover(); reason != nil {
			b.logf("panic handling update %d: %v", update.ID, reason)
		}
	}()

	from := update.From()
	if from == nil || from.ID != b.Cfg.AdminID {
		return
	}

	switch {
	case update.CallbackQuery != nil:
		b.handleCallback(ctx, update.CallbackQuery)
	case update.Message != nil:
		b.handleMessage(ctx, update.Message)
	}
}

func (b *Bot) handleMessage(ctx context.Context, message *tg.Message) {
	text := strings.TrimSpace(message.Text)
	if command, ok := strings.CutPrefix(text, "/"); ok {
		if name, _, found := strings.Cut(command, "@"); found {
			command = name
		}
		command, _, _ = strings.Cut(command, " ")
		b.handleCommand(ctx, command)
		return
	}
	if b.dialogs.current() != nil {
		b.handleDialogInput(ctx, text)
		return
	}
	b.sendScreen(ctx, scr(renderMain()))
}

func (b *Bot) handleCommand(ctx context.Context, command string) {
	// A command starts a fresh topic; a half-finished dialog would swallow the next
	// message as its answer.
	if command != "cancel" {
		b.dialogs.clear()
	}
	switch command {
	case "start", "menu", "help":
		b.sendScreen(ctx, scr(renderMain()))
	case "status":
		b.sendScreen(ctx, b.buildStatus(ctx))
	case "devices":
		b.sendScreen(ctx, b.buildDevices(ctx))
	case "tunnels":
		b.sendScreen(ctx, b.buildTunnels(ctx))
	case "deploy":
		b.sendScreen(ctx, b.buildDeployPreview(ctx))
	case "subs":
		b.sendScreen(ctx, b.buildSubs(ctx))
	case "routes":
		b.sendScreen(ctx, b.buildRoutes(ctx))
	case "logs":
		b.sendScreen(ctx, b.buildLogsMenu(ctx))
	case "host":
		b.sendScreen(ctx, b.buildHost(ctx))
	case "settings":
		b.sendScreen(ctx, b.buildSettings())
	case "cancel":
		if b.dialogs.current() == nil {
			b.send(ctx, "Нечего отменять.", nil)
			return
		}
		b.dialogs.clear()
		b.send(ctx, "✖️ Диалог отменён.", nil)
	default:
		b.sendScreen(ctx, scr(renderMain()))
	}
}

// result is what a callback handler reports back to the tap: a toast, or an alert
// dialog for refusals worth reading.
type result struct {
	toast string
	alert bool
}

func (b *Bot) handleCallback(ctx context.Context, callback *tg.CallbackQuery) {
	parts := strings.Split(callback.Data, ":")
	outcome := b.routeCallback(ctx, callback, parts)
	if err := b.API.AnswerCallbackQuery(ctx, callback.ID, outcome.toast, outcome.alert); err != nil {
		b.logf("answerCallbackQuery: %v", err)
	}
}

func (b *Bot) routeCallback(ctx context.Context, cb *tg.CallbackQuery, parts []string) result {
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	var args []string
	if len(parts) > 2 {
		args = parts[2:]
	}

	switch parts[0] {
	case "m":
		return b.show(ctx, cb, scr(renderMain()))
	case "st":
		return b.show(ctx, cb, b.buildStatus(ctx))
	case "dev":
		return b.routeDevices(ctx, cb, action, args)
	case "tun":
		return b.routeTunnels(ctx, cb, action, args)
	case "dep":
		return b.routeDeploy(ctx, cb, action, args)
	case "sub":
		return b.routeSubs(ctx, cb, action, args)
	case "rt":
		return b.show(ctx, cb, b.buildRoutes(ctx))
	case "log":
		return b.routeLogs(ctx, cb, action, args)
	case "host":
		return b.routeHost(ctx, cb, action)
	case "set":
		return b.routeSettings(ctx, cb, action, args)
	default:
		return result{toast: "Не понимаю эту кнопку"}
	}
}

// screen is one rendered view: what to say and which buttons to offer.
type screen struct {
	text   string
	markup *tg.InlineKeyboardMarkup
}

// scr adapts the renderers' (text, keyboard) pairs; its parameters match their
// results exactly so calls compose as scr(renderX(...)).
func scr(text string, markup *tg.InlineKeyboardMarkup) screen {
	return screen{text: text, markup: markup}
}

// show renders a screen into the tapped message, falling back to a fresh one.
func (b *Bot) show(ctx context.Context, cb *tg.CallbackQuery, view screen) result {
	if cb == nil || cb.Message == nil {
		b.sendScreen(ctx, view)
		return result{}
	}
	if err := b.API.EditMessageText(ctx, cb.Message.Chat.ID, cb.Message.ID, view.text, view.markup); err != nil {
		b.logf("editMessageText: %v", err)
		b.sendScreen(ctx, view)
	}
	return result{}
}

func (b *Bot) sendScreen(ctx context.Context, view screen) {
	if _, err := b.API.SendMessage(ctx, b.Cfg.AdminID, view.text, view.markup); err != nil {
		b.logf("sendMessage: %v", err)
	}
}

// send delivers a plain notification-style message to the admin.
func (b *Bot) send(ctx context.Context, text string, markup *tg.InlineKeyboardMarkup) {
	b.sendScreen(ctx, screen{text: text, markup: markup})
}
