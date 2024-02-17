package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

type TOKEN_ELEVATION struct {
	TokenIsElevated uint32
}

const port = "22"
const TokenElevation = 20

// This is a placeholder for a private key. In practice, generate a secure private key and store/load it securely.
var (
	RSAPK      *rsa.PrivateKey
	privateKey string
)

func handle(e error) {
	if e != nil {
		fmt.Println("PANIC: Something internal went wrong, this text should never be visible!!!")
		fmt.Println(e)
		os.Exit(-1)
	}
}

func RunningAsAdmin() bool {
	var tokenHandle syscall.Token
	currentProcess, _ := syscall.GetCurrentProcess()

	err := syscall.OpenProcessToken(currentProcess, syscall.TOKEN_QUERY, &tokenHandle)
	handle(err)
	defer syscall.CloseHandle(syscall.Handle(tokenHandle))

	var elevation TOKEN_ELEVATION
	var returnedLen uint32
	err = syscall.GetTokenInformation(tokenHandle, TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	handle(err)

	return elevation.TokenIsElevated != 0
}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}

	return pem.EncodeToMemory(privBlock)
}

func main() {
	if !RunningAsAdmin() {
		println("Re-run as admin.")
		os.Exit(0)
	}

	RSAPK, _ = generatePrivateKey(2048)
	privateKey = string(encodePrivateKeyToPEM(RSAPK))

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}

	private, err := ssh.ParsePrivateKey([]byte(privateKey))
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	config.AddHostKey(private)

	// Consider using a non-standard port for testing as binding to port 22 requires root privileges.
	listener, err := net.Listen("tcp", "localhost:"+port)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", port, err)
	}
	log.Printf("Listening on %s...", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		go handleConn(conn, config)
	}
}

func handleConn(netConn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, config)
	if err != nil {
		log.Printf("Failed to handshake: %v", err)
		return
	}
	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// Discard all incoming requests but respond to keep-alives
	go ssh.DiscardRequests(reqs)

	// Handle channels
	for newChannel := range chans {
		// Channels of type "session" are typically expected to be shells, but we're creating a limbo state.
		if newChannel.ChannelType() == "session" {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("Could not accept channel: %v", err)
				continue
			}

			go func() {
				// Initially, set a flag to false indicating no PTY has been allocated.
				ptyAllocated := false

				for req := range requests {
					switch req.Type {
					case "pty-req":
						// The client requests a PTY.
						if req.WantReply {
							req.Reply(true, nil) // Acknowledge the PTY request positively.
							ptyAllocated = true
						}
					case "shell":
						// The client requests a shell.
						if req.WantReply {
							req.Reply(true, nil) // Indicate success to the shell request.
						}

						// If a PTY has been allocated, you can proceed to display your message.
						if ptyAllocated {
							channel.Write([]byte("Permission denied, please try again.\n\r>>> ERR: SESSION HIJACKED!\n\r>>> Oh Noes! Yuor ssh session haz been hijacks!!1!\n\r>>> BYE BYE! (~>o<~)\r\nConnection forcibly client_loop: send disconnect: Connection reset\n\r"))

							go func() {
								for {
									channel.Write([]byte("\a"))
								}
							}()

						}
					case "exec":
						// Explicitly reject exec requests.
						if req.WantReply {
							req.Reply(false, nil)
						}
					default:
						// Optionally handle other request types.
						if req.WantReply {
							req.Reply(false, nil)
						}
					}

				}

				channel.Close() // Close the session after handling the initial requests.
			}()
		} else {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}
