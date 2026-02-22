package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

type sshCompatServer struct {
	ln      net.Listener
	mu      sync.Mutex
	closed  bool
	clients map[net.Conn]struct{}
}

func startSSHCompatServer(bindIP string, port int, password string) (*sshCompatServer, error) {
	if port <= 0 {
		return nil, fmt.Errorf("invalid ssh compat port")
	}
	if password == "" {
		return nil, fmt.Errorf("empty ssh compat password")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "root" && string(pass) == password {
				return nil, nil
			}
			return nil, fmt.Errorf("ssh auth failed")
		},
	}
	cfg.AddHostKey(signer)
	addr := bindIP + ":" + strconv.Itoa(port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &sshCompatServer{
		ln:      ln,
		clients: make(map[net.Conn]struct{}),
	}
	go s.serve(cfg)
	return s, nil
}

func (s *sshCompatServer) serve(cfg *ssh.ServerConfig) {
	for {
		nConn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = nConn.Close()
			return
		}
		s.clients[nConn] = struct{}{}
		s.mu.Unlock()

		go func(conn net.Conn) {
			defer func() {
				s.mu.Lock()
				delete(s.clients, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()

			_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
			if err != nil {
				return
			}

			go func() {
				for req := range reqs {
					allowed := req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward" || req.Type == "keepalive@openssh.com"
					if req.WantReply {
						_ = req.Reply(allowed, nil)
					}
				}
			}()

			for ch := range chans {
				_ = ch.Reject(ssh.UnknownChannelType, "unsupported")
			}
		}(nConn)
	}
}

func (s *sshCompatServer) stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	clients := make([]net.Conn, 0, len(s.clients))
	for conn := range s.clients {
		clients = append(clients, conn)
	}
	s.mu.Unlock()

	_ = s.ln.Close()
	for _, conn := range clients {
		_ = conn.Close()
	}
}
