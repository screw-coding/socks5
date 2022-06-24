package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const (
	SOCKS5Version = 0x05
	ReservedField = 0x00
)

type Server interface {
	Run() error
}

type ServerSocks5 struct {
	IP     string
	Port   int
	Config *Config
}

type Config struct {
	AuthMethod      Method
	PassWordChecker func(username, passwd string) bool
}

func initConfig(config *Config) error {
	if config.AuthMethod == MethodUseAndPassWD && config.PassWordChecker == nil {
		return errors.New("no password checker")
	}
	return nil
}

func (s *ServerSocks5) Run() error {
	// Initializer server configuration
	if err := initConfig(s.Config); err != nil {
		return err
	}
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listen, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	log.Printf("run socks5 server successful on %s", address)
	for {
		con, err := listen.Accept()
		if err != nil {
			log.Printf("connection failure from %s: %s\n", con.RemoteAddr(), err)
		}
		go func() {
			defer con.Close()
			err = handleConnection(con, s.Config)
			if err != nil {
				log.Printf("handle connection error: %s\n", err)
			}
		}()
	}
}

func handleConnection(con net.Conn, config *Config) error {
	// 处理 socks5 协议的协商过程
	err := auth(con, config)
	if err != nil {
		return err
	}
	// 请求过程
	targetConn, err := request(con)
	if err != nil {
		return err
	}
	// 转发过程
	return forward(con, targetConn)
}

func forward(conn net.Conn, targetConn net.Conn) error {
	defer targetConn.Close()
	go io.Copy(targetConn, conn)
	_, err := io.Copy(conn, targetConn)
	return err
}

func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait))
	}()
	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait))
	wg.Wait()

	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}

	if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) {
		return err1
	}

	return nil
}

func auth(conn net.Conn, config *Config) error {
	// Read client auth message
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}
	log.Println(clientMessage.Version, clientMessage.NMethods, clientMessage.Methods)

	// check if the auth method is supported
	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == config.AuthMethod {
			acceptable = true
		}
	}

	if !acceptable {
		_ = NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}

	if err := NewServerAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}

	if config.AuthMethod == MethodUseAndPassWD {
		cpm, err := NewClientPasswordMessage(conn)
		if err != nil {
			return err
		}

		if !config.PassWordChecker(cpm.Username, cpm.Passwd) {
			// 认证失败
			_ = WriteServerPasswdMessage(conn, PasswordAuthFailure)
			return ErrPasswordAuthFailure
		}
		if err := WriteServerPasswdMessage(conn, PasswordAuthSuccess); err != nil {
			return err
		}
	}
	return nil
}

func request(conn net.Conn) (net.Conn, error) {
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}
	// 暂时只支持 command connect
	// 地址暂时只支持 IPv4 和 DomainName
	if message.Cmd != CommandConnect {
		return nil, WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
	}

	if message.AddressType == TypeIPv6 {
		return nil, WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
	}

	// 请求访问目标 TCP 服务
	address := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		log.Printf("connection Erro %s", err)
		// 根据错误来写这个错误的返回类型
		return nil, WriteRequestFailureMessage(conn, ReplyConnectionRefused)
	}
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	// FIXME
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, TypeIPv4, uint16(addr.Port))
}

var (
	ErrVersionNotSupported     = errors.New("protocol version not supported")
	ErrCommandNotSupported     = errors.New("request command not supported")
	ErrInvalidReservedField    = errors.New("invalid reserved field")
	ErrAddressTypeNotSupported = errors.New("address Type not supported")

	ErrMethodVersionNotSupport = errors.New("sub-negotiation method version not supported")
	ErrPasswordAuthFailure     = errors.New("error authenticating username/passewd")
)
