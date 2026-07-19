package telegram

// The wire types mirror the Bot API fields the bot actually reads; everything else
// an update carries is deliberately dropped at decode.

// Update is one event from getUpdates.
type Update struct {
	ID            int64          `json:"update_id"`
	Message       *Message       `json:"message"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
}

// From reports who caused the update, whichever kind it is. Nil means the update
// carries no sender, and an authorizer must treat that as a stranger.
func (u Update) From() *User {
	switch {
	case u.CallbackQuery != nil:
		return &u.CallbackQuery.From
	case u.Message != nil:
		return u.Message.From
	default:
		return nil
	}
}

type Message struct {
	ID   int64  `json:"message_id"`
	From *User  `json:"from"`
	Chat Chat   `json:"chat"`
	Text string `json:"text"`
}

type Chat struct {
	ID int64 `json:"id"`
}

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// CallbackQuery is a tap on an inline keyboard button.
type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
}

type BotCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}
