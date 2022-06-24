package main

import (
	"github.com/jaymie9019/socks5"
	"log"
)

func main() {
	users := map[string]string{
		"admin":  "123456",
		"jaymie": "jaymie123",
	}

	server := socks5.ServerSocks5{
		IP:   "localhost",
		Port: 8888,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodUseAndPassWD,
			PassWordChecker: func(username, passwd string) bool {
				wantPasswd, ok := users[username]
				if !ok {
					return false
				}
				return wantPasswd == passwd
			},
		},
	}
	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}

}
