package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var ciph cipher.Block

func init() {
	var err error
	ciph, err = aes.NewCipher([]byte("YELLOW SUBMARINE"))

	if err != nil {
		panic(err)
	}
}

// pkcs#7 padding
func Test9(t *testing.T) {
	result := pad([]byte("YELLOW SUBMARINE"), 20)

	assert.Equal(t, "YELLOW SUBMARINE\x04\x04\x04\x04", string(result))
}

/*
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the
fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the
cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake
0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead
of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function
from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of
all ASCII 0 (\x00\x00\x00 &c)
*/
func Test10(t *testing.T) {
	// IV ^ first block -> cipher encrypt
	// previous block ^ next block -> cipher encrypt
	ciphertext := loadb64(t, "10.txt")

	plaintext := make([]byte, len(ciphertext))
	prev := []byte(strings.Repeat("\x00", 16))

	for i := 0; i < len(ciphertext); i += 16 {
		block := make([]byte, 16)
		ciph.Decrypt(block, ciphertext[i:i+16])
		plaintext = append(plaintext, xor(prev, block)...)
		prev = ciphertext[i : i+16]
	}

	fmt.Println(string(plaintext))
}

func Test10a(t *testing.T) {
	plaintext := pad([]byte("taco bell is #1 taco bell is #2 oh no"), 16)
	ciphertext := make([]byte, len(plaintext))

	previousCipherblock := []byte(strings.Repeat("\x00", 16))

	for i := 0; i < len(plaintext); i += 16 {
		block := xor(previousCipherblock, plaintext[i:i+16])
		ciph.Encrypt(ciphertext[i:i+16], block)
		previousCipherblock = ciphertext[i : i+16]
	}

	undone := make([]byte, len(ciphertext))

	prev := []byte(strings.Repeat("\x00", 16))

	for i := 0; i < len(ciphertext); i += 16 {
		plaintext := make([]byte, 16)
		ciph.Decrypt(plaintext, ciphertext[i:i+16])
		undone = append(undone, xor(prev, plaintext)...)
		prev = ciphertext[i : i+16]
	}

	fmt.Println(string(undone))
}
