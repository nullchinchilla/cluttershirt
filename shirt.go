package cluttershirt

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"time"
)

type blurb struct {
	readChug   cipher.Stream
	writeChug  cipher.Stream
	underlying net.Conn
}

func sechash(m, k []byte) []byte {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return mac.Sum(nil)
}

// Server negotiates obfuscation on a network connection, acting as the server. The secret must be provided.
func Server(secret []byte, transport net.Conn) (net.Conn, error) {
	// Client needs to send proof that they actually have our secret
	proof := make([]byte, 64)
	_, err := io.ReadFull(transport, proof)
	if err != nil {
		return nil, err
	}
	// We need to verify proof
	nonce := proof[:32]
	hash := proof[32:]
	if subtle.ConstantTimeCompare(sechash(secret, nonce), hash) != 1 {
		return nil, errors.New("Client did not give the right proof")
	}
	// Generate our ephemeral keys
	ourKeys := dhGenKey(1536)

	// Send our public key
	_, err = transport.Write(ourKeys.Public)
	if err != nil {
		return nil, err
	}

	// Read their public key
	theirPublic := make([]byte, 1536/8)
	_, err = io.ReadFull(transport, theirPublic)
	if err != nil {
		return nil, err
	}
	// Compute shared secret
	shSecret := udhSecret(ourKeys.Private, theirPublic)
	// Read and write keys
	rKey := sechash(shSecret, []byte("cluttershirt-upstream-key"))
	wKey := sechash(shSecret, []byte("cluttershirt-downstream-key"))
	// Create struct
	toret := new(blurb)

	toret.readChug, _ = rc4.NewCipher(rKey)
	toret.writeChug, _ = rc4.NewCipher(wKey)

	dummy := make([]byte, 1536)
	toret.readChug.XORKeyStream(dummy, dummy)
	toret.writeChug.XORKeyStream(dummy, dummy)

	toret.underlying = transport
	return toret, nil
}

// Client negotiates low-level obfuscation as a client. The server
// secret must be given so that the client can prove knowledge.
func Client(secret []byte, transport net.Conn) (net.Conn, error) {
	// Prove knowledge to client first
	nonce := make([]byte, 32)
	rand.Read(nonce)
	hash := sechash(secret, nonce)
	_, err := transport.Write(append(nonce, hash...))
	if err != nil {
		return nil, err
	}
	// Read their public key
	theirPublic := make([]byte, 1536/8)
	_, err = io.ReadFull(transport, theirPublic)
	if err != nil {
		return nil, err
	}
	// Make our keys
	ourKeys := dhGenKey(1536)
	// Send our public key
	_, err = transport.Write(ourKeys.Public)
	if err != nil {
		return nil, err
	}
	// Compute shared secret
	sharedSecret := udhSecret(ourKeys.Private, theirPublic)
	// Derive keys
	readKey := sechash(sharedSecret, []byte("cluttershirt-downstream-key"))
	writeKey := sechash(sharedSecret, []byte("cluttershirt-upstream-key"))
	toret := new(blurb)
	toret.readChug, _ = rc4.NewCipher(readKey)
	toret.writeChug, _ = rc4.NewCipher(writeKey)

	dummy := make([]byte, 1536)
	toret.readChug.XORKeyStream(dummy, dummy)
	toret.writeChug.XORKeyStream(dummy, dummy)
	toret.underlying = transport

	return toret, nil
}

func (ctx *blurb) Read(bts []byte) (int, error) {
	number, err := ctx.underlying.Read(bts)
	if err != nil {
		return number, err
	}
	ctx.readChug.XORKeyStream(bts[:number], bts[:number])
	return number, err
}

func (ctx *blurb) Write(bts []byte) (int, error) {
	buff := make([]byte, len(bts))
	ctx.writeChug.XORKeyStream(buff, bts)
	return ctx.underlying.Write(buff)
}

func (ctx *blurb) Close() error {
	return ctx.underlying.Close()
}

func (ctx *blurb) LocalAddr() net.Addr {
	return ctx.underlying.LocalAddr()
}

func (ctx *blurb) RemoteAddr() net.Addr {
	return ctx.underlying.RemoteAddr()
}

func (ctx *blurb) SetDeadline(t time.Time) error {
	return ctx.underlying.SetDeadline(t)
}

func (ctx *blurb) SetReadDeadline(t time.Time) error {
	return ctx.underlying.SetReadDeadline(t)
}

func (ctx *blurb) SetWriteDeadline(t time.Time) error {
	return ctx.underlying.SetWriteDeadline(t)
}
