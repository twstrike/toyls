package toyls

import (
	"crypto/tls"
	"errors"

	. "gopkg.in/check.v1"
)

type record struct {
	contentType ContentType
	body        []byte
}

func pipeHandshakers(c, s handshaker) {
	client, server := newPipe()
	c.setRecordProtocol(client)
	s.setRecordProtocol(server)
}

func newPipe() (recordProtocol, recordProtocol) {
	left := make(chan record, 1)
	right := make(chan record, 1)

	return &dummyRecordProtocol{left, right}, &dummyRecordProtocol{right, left}
}

type dummyRecordProtocol struct {
	read  <-chan record
	write chan<- record
}

func (r *dummyRecordProtocol) readRecord(c ContentType) ([]byte, error) {
	record := <-r.read
	if record.contentType != c {
		return record.body, errors.New("wrong content type")
	}

	return record.body, nil
}

func (r *dummyRecordProtocol) writeRecord(c ContentType, b []byte) error {
	r.write <- record{c, b}
	return nil
}

func (s *ToySuite) TestFullHandshakeNew(c *C) {
	var err error

	client := newClient()
	server := newServer()

	pem := []byte(rsaCertPEM + rsaKeyPEM)
	server.handshaker.(*handshakeServer).Certificate, err = tls.X509KeyPair(pem, pem)
	c.Assert(err, IsNil)

	pipeHandshakers(client.handshaker, server.handshaker)

	ok := make(chan bool, 0)
	go func() {
		server.doHandshake()
		ok <- true
	}()

	client.Handshake()
	c.Assert(err, IsNil)
	<-ok

	//You can start to exchange encrypted data
}
