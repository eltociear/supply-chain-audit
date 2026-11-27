package notify

import (
	"fmt"
	"net/http"
	"net/url"
)

// Send posts a message with the caller's bot token.
func Send(token, chat, text string) error {
	_, err := http.PostForm(fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token),
		url.Values{"chat_id": {chat}, "text": {text}})
	return err
}
