// Package telegram is a minimal Bot API client: the ten methods the bot needs,
// on the standard library.
//
// A library would bring its own routing and middleware model on top of these same
// HTTP calls, and the delivery layer owns routing anyway. Long polling only -- the
// hub's firewall admits nothing inbound, so webhooks are not an option.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	Token string
	// BaseURL defaults to the public Bot API; tests point it at a local server.
	BaseURL string
	HTTP    *http.Client
}

// APIError is a refusal from the Bot API, with the retry hint surfaced so the send
// path can honor rate limits instead of hammering through them.
type APIError struct {
	Method      string
	Code        int
	Description string
	RetryAfter  time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("telegram %s: %s (code %d)", e.Method, e.Description, e.Code)
}

func (c Client) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return "https://api.telegram.org"
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// call posts one method and decodes the result. A 429 with retry_after is waited
// out and retried a couple of times; anything else is the caller's problem.
func (c Client) call(ctx context.Context, method string, payload io.Reader, contentType string, result any) error {
	body, err := io.ReadAll(payload)
	if err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	for attempt := 0; ; attempt++ {
		err := c.post(ctx, method, bytes.NewReader(body), contentType, result)
		var refusal *APIError
		if attempt < 2 && errors.As(err, &refusal) && refusal.RetryAfter > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(refusal.RetryAfter):
				continue
			}
		}
		return err
	}
}

func (c Client) post(ctx context.Context, method string, payload io.Reader, contentType string, result any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/bot%s/%s", c.baseURL(), c.Token, method), payload)
	if err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	request.Header.Set("Content-Type", contentType)

	response, err := c.httpClient().Do(request)
	if err != nil {
		// The transport error carries the request URL, and the URL carries the token;
		// unwrap so neither reaches a log.
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	defer func() { _ = response.Body.Close() }()

	var envelope struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
		ErrorCode   int             `json:"error_code"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return fmt.Errorf("telegram %s: decode response: %w", method, err)
	}
	if !envelope.OK {
		return &APIError{
			Method:      method,
			Code:        envelope.ErrorCode,
			Description: envelope.Description,
			RetryAfter:  time.Duration(envelope.Parameters.RetryAfter) * time.Second,
		}
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("telegram %s: decode result: %w", method, err)
	}
	return nil
}

func (c Client) callJSON(ctx context.Context, method string, payload any, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("telegram %s: encode request: %w", method, err)
	}
	return c.call(ctx, method, bytes.NewReader(body), "application/json", result)
}

func (c Client) GetMe(ctx context.Context) (User, error) {
	var me User
	err := c.callJSON(ctx, "getMe", struct{}{}, &me)
	return me, err
}

// GetUpdates long-polls for up to timeout seconds. The caller's context has to
// outlive that timeout, or every empty poll looks like a failure.
func (c Client) GetUpdates(ctx context.Context, offset int64, timeout int) ([]Update, error) {
	var updates []Update
	err := c.callJSON(ctx, "getUpdates", map[string]any{
		"offset":          offset,
		"timeout":         timeout,
		"allowed_updates": []string{"message", "callback_query"},
	}, &updates)
	return updates, err
}

// SendMessage sends HTML-formatted text, optionally with an inline keyboard.
func (c Client) SendMessage(ctx context.Context, chatID int64, text string, keyboard *InlineKeyboardMarkup) (Message, error) {
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
		"link_preview_options": map[string]any{
			"is_disabled": true,
		},
	}
	if keyboard != nil {
		payload["reply_markup"] = keyboard
	}
	var message Message
	err := c.callJSON(ctx, "sendMessage", payload, &message)
	return message, err
}

// EditMessageText rewrites a sent message. Rewriting it with what it already says
// is not an error here: live progress editors converge on a final text, and the
// API's "message is not modified" refusal would turn that into noise.
func (c Client) EditMessageText(ctx context.Context, chatID, messageID int64, text string, keyboard *InlineKeyboardMarkup) error {
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       text,
		"parse_mode": "HTML",
		"link_preview_options": map[string]any{
			"is_disabled": true,
		},
	}
	if keyboard != nil {
		payload["reply_markup"] = keyboard
	}
	err := c.callJSON(ctx, "editMessageText", payload, nil)
	return ignoreNotModified(err)
}

func (c Client) EditMessageReplyMarkup(ctx context.Context, chatID, messageID int64, keyboard *InlineKeyboardMarkup) error {
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
	}
	if keyboard != nil {
		payload["reply_markup"] = keyboard
	}
	err := c.callJSON(ctx, "editMessageReplyMarkup", payload, nil)
	return ignoreNotModified(err)
}

// AnswerCallbackQuery acknowledges a button tap; without it the client shows a
// spinner until it times out.
func (c Client) AnswerCallbackQuery(ctx context.Context, callbackID, text string, showAlert bool) error {
	return c.callJSON(ctx, "answerCallbackQuery", map[string]any{
		"callback_query_id": callbackID,
		"text":              text,
		"show_alert":        showAlert,
	}, nil)
}

func (c Client) DeleteMessage(ctx context.Context, chatID, messageID int64) error {
	return c.callJSON(ctx, "deleteMessage", map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
	}, nil)
}

func (c Client) SetMyCommands(ctx context.Context, commands []BotCommand) error {
	return c.callJSON(ctx, "setMyCommands", map[string]any{"commands": commands}, nil)
}

// SendDocument uploads a file from memory. Nothing the bot sends exists on disk --
// a client profile in particular must not.
func (c Client) SendDocument(ctx context.Context, chatID int64, filename string, content []byte, caption string) (Message, error) {
	return c.upload(ctx, "sendDocument", "document", chatID, filename, content, caption)
}

func (c Client) SendPhoto(ctx context.Context, chatID int64, filename string, content []byte, caption string) (Message, error) {
	return c.upload(ctx, "sendPhoto", "photo", chatID, filename, content, caption)
}

func (c Client) upload(ctx context.Context, method, field string, chatID int64, filename string, content []byte, caption string) (Message, error) {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	if err := form.WriteField("chat_id", fmt.Sprint(chatID)); err != nil {
		return Message{}, fmt.Errorf("telegram %s: %w", method, err)
	}
	if caption != "" {
		if err := form.WriteField("caption", caption); err != nil {
			return Message{}, fmt.Errorf("telegram %s: %w", method, err)
		}
		if err := form.WriteField("parse_mode", "HTML"); err != nil {
			return Message{}, fmt.Errorf("telegram %s: %w", method, err)
		}
	}
	part, err := form.CreateFormFile(field, filename)
	if err != nil {
		return Message{}, fmt.Errorf("telegram %s: %w", method, err)
	}
	if _, err := part.Write(content); err != nil {
		return Message{}, fmt.Errorf("telegram %s: %w", method, err)
	}
	if err := form.Close(); err != nil {
		return Message{}, fmt.Errorf("telegram %s: %w", method, err)
	}

	var message Message
	err = c.call(ctx, method, &body, form.FormDataContentType(), &message)
	return message, err
}

func ignoreNotModified(err error) error {
	var refusal *APIError
	if errors.As(err, &refusal) && strings.Contains(refusal.Description, "message is not modified") {
		return nil
	}
	return err
}
