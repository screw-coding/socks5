package socks5

import (
	"bytes"
	"fmt"
	"log"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI}
		reader := bytes.NewReader(b)

		message, err := NewClientAuthMessage(reader)
		if err != nil {
			t.Fatalf("want errors = nil but got %s", err)
		}

		if message.Version != SOCKS5Version {
			t.Fatalf("want version is 0x05, but got %d", message.Version)
		}

		if message.NMethods != 2 {
			t.Fatalf("want nmtethos = 2, but got %d", message.Version)
		}

		if !reflect.DeepEqual(message.Methods, []byte{0x00, 0x01}) {
			t.Fatalf("want methos: %v, but got %v", []byte{0x00, 0x01}, message.Methods)
		}
	})

	t.Run("methods length is shorter than methods", func(t *testing.T) {
		b := []byte{SOCKS5Version, 2, 0x00}
		reader := bytes.NewReader(b)

		_, err := NewClientAuthMessage(reader)
		if err == nil {
			t.Fatalf("want errors != nill but got nil")
		}

	})
}

func TestNewClientPasswordMessage(t *testing.T) {
	t.Run("valid password auth message", func(t *testing.T) {
		username, passwd := "admin", "123456"

		var buff bytes.Buffer
		buff.WriteByte(UsernameMethodVersion)
		buff.WriteByte(0x05)
		buff.WriteString(username)
		buff.WriteByte(0x06)
		buff.WriteString(passwd)

		fmt.Println(buff)
		message, err := NewClientPasswordMessage(&buff)
		if err != nil {
			log.Fatalf("want error = nil but got %s", err)
		}

		if message.Username != username {
			log.Fatalf("want username = %s but got %s", username, message.Username)
		}

		if message.Passwd != passwd {
			log.Fatalf("want passwd = %s but got %s", passwd, message.Passwd)
		}

	})
}
