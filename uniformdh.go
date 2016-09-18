package cluttershirt

import (
	"crypto/rand"
	"math/big"
	"time"
)

type dhPK []byte
type dhSK []byte
type udhKeys struct {
	Public  dhPK
	Private dhSK
}

func udhSecret(lsk dhSK, rpk dhPK) []byte {
	// Constant time when completes within 250 ms
	retchan := make(chan []byte)
	go func() {
		bitlen := len(lsk) * 8
		// checks
		if bitlen != 1536 && bitlen != 2048 {
			panic("Why are you trying to generate DH key with wrong bitlen?")
		}
		var group *big.Int
		group = dhGroup5
		retchan <- big.NewInt(0).Exp(big.NewInt(0).SetBytes(rpk),
			big.NewInt(0).SetBytes(lsk), group).Bytes()
	}()
	<-time.After(time.Second / 4)
	return <-retchan
}

func dhGenKey(bitlen int) udhKeys {
	retchan := make(chan udhKeys)
	go func() {
		// checks
		if bitlen != 1536 {
			panic("Why are you trying to generate DH key with wrong bitlen?")
		}
		var group *big.Int
		group = dhGroup5
		// randomly generate even private key
		pub := dhPK(make([]byte, bitlen/8))
		priv := dhSK(make([]byte, bitlen/8))
		rand.Read(priv)
		priv[bitlen/8-1] /= 2
		priv[bitlen/8-1] *= 2
		privBnum := big.NewInt(0).SetBytes(priv)
	retry:
		// generate public key
		pubBnum := big.NewInt(0).Exp(big.NewInt(2), privBnum, group)
		ggg := make([]byte, 1)
		rand.Read(ggg)
		if ggg[0]%2 == 0 {
			pubBnum = big.NewInt(0).Sub(group, pubBnum)
		}
		// Obtain pubkey
		candid := pubBnum.Bytes()
		if len(candid) != len(pub) {
			goto retry
		}
		copy(pub, candid)
		retchan <- udhKeys{pub, priv}
	}()
	return <-retchan
}
