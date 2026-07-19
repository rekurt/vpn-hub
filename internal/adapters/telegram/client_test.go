package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAPI records what the client sent and answers with scripted responses.
type fakeAPI struct {
	t         *testing.T
	responses map[string][]string
	calls     []string
	bodies    map[string][]string
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	t.Helper()
	fake := &fakeAPI{t: t, responses: map[string][]string{}, bodies: map[string][]string{}}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	return fake, server
}

func (f *fakeAPI) respond(method string, bodies ...string) {
	f.responses[method] = append(f.responses[method], bodies...)
}

func (f *fakeAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	parts := strings.Split(request.URL.Path, "/")
	method := parts[len(parts)-1]
	body, _ := io.ReadAll(request.Body)
	f.calls = append(f.calls, method)
	f.bodies[method] = append(f.bodies[method], string(body))

	queue := f.responses[method]
	if len(queue) == 0 {
		f.t.Errorf("unexpected call %s", method)
		fmt.Fprint(writer, `{"ok":true,"result":true}`)
		return
	}
	f.responses[method] = queue[1:]
	fmt.Fprint(writer, queue[0])
}

func client(server *httptest.Server) Client {
	return Client{Token: "12345:SECRET", BaseURL: server.URL}
}

func TestSendMessageSpeaksHTMLAndCarriesTheKeyboard(t *testing.T) {
	t.Parallel()
	fake, server := newFakeAPI(t)
	fake.respond("sendMessage", `{"ok":true,"result":{"message_id":7,"chat":{"id":42}}}`)

	keyboard := &InlineKeyboardMarkup{InlineKeyboard: [][]InlineKeyboardButton{{
		{Text: "Статус", CallbackData: "st"},
	}}}
	message, err := client(server).SendMessage(context.Background(), 42, "<b>привет</b>", keyboard)
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if message.ID != 7 {
		t.Fatalf("unexpected message %+v", message)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(fake.bodies["sendMessage"][0]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["parse_mode"] != "HTML" || payload["chat_id"] != float64(42) {
		t.Fatalf("unexpected payload %v", payload)
	}
	if payload["reply_markup"] == nil {
		t.Fatal("the keyboard was dropped")
	}
}

func TestRetryAfterIsHonored(t *testing.T) {
	t.Parallel()
	fake, server := newFakeAPI(t)
	fake.respond("sendMessage",
		`{"ok":false,"error_code":429,"description":"Too Many Requests","parameters":{"retry_after":1}}`,
		`{"ok":true,"result":{"message_id":8,"chat":{"id":42}}}`)

	message, err := client(server).SendMessage(context.Background(), 42, "hi", nil)
	if err != nil {
		t.Fatalf("expected the retry to succeed, got %v", err)
	}
	if message.ID != 8 || len(fake.calls) != 2 {
		t.Fatalf("expected two attempts, got %v", fake.calls)
	}
}

func TestRefusalsSurfaceAsAPIErrors(t *testing.T) {
	t.Parallel()
	fake, server := newFakeAPI(t)
	fake.respond("sendMessage", `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`)

	_, err := client(server).SendMessage(context.Background(), 42, "hi", nil)
	if err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("expected the description to surface, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("the token leaked into the error: %v", err)
	}
}

// Progress editors converge on a final text; the API's complaint about editing a
// message into itself must not surface as a failure.
func TestEditingIntoTheSameTextIsFine(t *testing.T) {
	t.Parallel()
	fake, server := newFakeAPI(t)
	fake.respond("editMessageText", `{"ok":false,"error_code":400,"description":"Bad Request: message is not modified"}`)

	if err := client(server).EditMessageText(context.Background(), 42, 7, "same", nil); err != nil {
		t.Fatalf("expected not-modified to be ignored, got %v", err)
	}
}

func TestSendDocumentUploadsMultipart(t *testing.T) {
	t.Parallel()
	fake, server := newFakeAPI(t)
	fake.respond("sendDocument", `{"ok":true,"result":{"message_id":9,"chat":{"id":42}}}`)

	_, err := client(server).SendDocument(context.Background(), 42, "laptop.conf", []byte("[Interface]"), "профиль")
	if err != nil {
		t.Fatalf("SendDocument: %v", err)
	}
	body := fake.bodies["sendDocument"][0]
	for _, expected := range []string{`filename="laptop.conf"`, "[Interface]", `name="document"`, `name="chat_id"`} {
		if !strings.Contains(body, expected) {
			t.Errorf("multipart body lacks %s", expected)
		}
	}
}

func TestGetUpdatesRequestsTheAllowedKinds(t *testing.T) {
	t.Parallel()
	fake, server := newFakeAPI(t)
	fake.respond("getUpdates", `{"ok":true,"result":[{"update_id":5,"message":{"message_id":1,"chat":{"id":42},"from":{"id":42},"text":"/start"}}]}`)

	updates, err := client(server).GetUpdates(context.Background(), 4, 25)
	if err != nil {
		t.Fatalf("GetUpdates: %v", err)
	}
	if len(updates) != 1 || updates[0].ID != 5 || updates[0].Message.Text != "/start" {
		t.Fatalf("unexpected updates %+v", updates)
	}
	if from := updates[0].From(); from == nil || from.ID != 42 {
		t.Fatalf("unexpected sender %+v", updates[0].From())
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(fake.bodies["getUpdates"][0]), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["offset"] != float64(4) || payload["timeout"] != float64(25) {
		t.Fatalf("unexpected payload %v", payload)
	}
}
