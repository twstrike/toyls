package toyls

import (
	"crypto/tls"
	"fmt"

	. "gopkg.in/check.v1"
)

func (s *ToySuite) TestFullHandshake(c *C) {
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

	fmt.Println("client (clientHello) ->")
	toSend := server.receive(m) //toSend = ServerHello, Certificate, ServerHelloDone

	fmt.Println("server (serverHello) ->")
	client.receive(toSend[0])
	fmt.Println("server (certificate) ->")
	client.receive(toSend[1])
	fmt.Println("server (serverHelloDone) ->")
	toSend = client.receive(toSend[2]) // toSend = ChangeCipherSpec, Finished

	fmt.Println("client (changeCipherSpec) ->")
	server.receive(toSend[0])
	fmt.Println("client (finished) ->")
	toSend = server.receive(toSend[1]) // toSend = ChangeCipherSpec, Finished

	fmt.Println("server (changeCipherSpec) ->")
	client.receive(toSend[0]) //changeCipherSpec
	fmt.Println("server (finished) ->")
	client.receive(toSend[1]) //finished

	//You can start to exchange encrypted data
}
