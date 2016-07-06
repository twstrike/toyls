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

	clientToReceive := <-serverToSend //serverToSends = ServerHello, Certificate, ServerHelloDone
	fmt.Println("server (serverHello) ->")
	clientIn.Write(clientToReceive[0])
	fmt.Println("server (certificate) ->")
	clientIn.Write(clientToReceive[1])
	fmt.Println("server (serverHelloDone) ->")
	clientIn.Write(clientToReceive[2])

	serverToReceive := <-clientToSend // clientToSends = ChangeCipherSpec, Finished

	fmt.Println("client (clientKeyExchange) ->")
	serverIn.Write(serverToReceive[0])
	fmt.Println("client (changeCipherSpec) ->")
	serverIn.Write(serverToReceive[1])
	fmt.Println("client (finished) ->")
	serverIn.Write(serverToReceive[2])

	clientToReceive = <-serverToSend // serverToSends = ChangeCipherSpec, Finished

	fmt.Println("server (changeCipherSpec) ->")
	clientIn.Write(clientToReceive[0])
	fmt.Println("server (finished) ->")
	clientIn.Write(clientToReceive[1])

	//You can start to exchange encrypted data
}
