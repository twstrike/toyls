package toyls

import (
	"crypto/tls"
	"fmt"

	. "gopkg.in/check.v1"
)

func (s *ToySuite) TestFullHandshake(c *C) {
	c.Skip("not finished")
	var err error

	client := newClient()
	server := newServer()

	pem := []byte(rsaCertPEM + rsaKeyPEM)
	server.handshakeServer.Certificate, err = tls.X509KeyPair(pem, pem)
	c.Assert(err, IsNil)

	//fmt.Printf("Certificate: %#v\n", server.handshakeServer.Certificate)

	//tls.Dial(...) -> TCP connection + sendHello
	m, err := client.hello()
	c.Assert(err, IsNil)

	serverIn := &mockConnIOReaderWriter{}
	clientIn := &mockConnIOReaderWriter{}
	serverToSend := server.receive(serverIn)
	clientToSend := client.receive(clientIn)

	fmt.Println("client (clientHello) ->")
	serverIn.Write(m)

	//serverToSends = ServerHello, Certificate, ServerHelloDone
	fmt.Println("server (serverHello) ->")
	clientIn.Write(<-serverToSend)
	fmt.Println("server (certificate) ->")
	clientIn.Write(<-serverToSend)
	fmt.Println("server (serverHelloDone) ->")
	clientIn.Write(<-serverToSend)

	// clientToSends = ChangeCipherSpec, Finished
	fmt.Println("client (clientKeyExchange) ->")
	serverIn.Write(<-clientToSend)
	fmt.Println("client (changeCipherSpec) ->")
	serverIn.Write(<-clientToSend)
	fmt.Println("client (finished) ->")
	serverIn.Write(<-clientToSend)

	// serverToSends = ChangeCipherSpec, Finished
	fmt.Println("server (changeCipherSpec) ->")
	clientIn.Write(<-serverToSend)
	fmt.Println("server (finished) ->")
	clientIn.Write(<-serverToSend)

	//You can start to exchange encrypted data
}
