package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

// Try single block of 16
func Test10a(t *testing.T) {
	ciphertext := cbcEncrypt(
		[]byte("taco bell is #1!"),
		defaultKey,
		[]byte(strings.Repeat("\x00", 16)),
	)

	plaintext := cbcDecrypt(
		ciphertext,
		defaultKey,
		[]byte(strings.Repeat("\x00", 16)),
	)

	assert.Equal(t, "taco bell is #1!", strings.TrimRight(string(plaintext), "\x04"))
}

// Try multiple blocks of 16
func Test10b(t *testing.T) {
	ciphertext := cbcEncrypt(
		[]byte("taco bell is #1!taco bell is #2!"),
		defaultKey,
		[]byte(strings.Repeat("\x00", 16)),
	)

	plaintext := cbcDecrypt(
		ciphertext,
		defaultKey,
		[]byte(strings.Repeat("\x00", 16)),
	)

	assert.Equal(t, "taco bell is #1!taco bell is #2!", strings.TrimRight(string(plaintext), "\x04"))
}

// Multiple blocks not exactly 16 size
func Test10c(t *testing.T) {
	ciphertext := cbcEncrypt(
		[]byte("taco bell is #1!taco bell is #2! oh no"),
		defaultKey,
		[]byte(strings.Repeat("\x00", 16)),
	)

	plaintext := cbcDecrypt(
		ciphertext,
		defaultKey,
		[]byte(strings.Repeat("\x00", 16)),
	)

	assert.Equal(t, "taco bell is #1!taco bell is #2! oh no", strings.TrimRight(string(plaintext), "\x04"))
}

func Test10d(t *testing.T) {
	ciphertext := loadb64(t, "10.txt")

	plaintext := cbcDecrypt(ciphertext, defaultKey, []byte(strings.Repeat("\x00", 16)))

	// TODO: Don't print this huge block just assert
	fmt.Println(string(plaintext))
}

/*
 Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a
random key and encrypts under it.

The function should look like:

encryption_oracle(your-input) => [MEANINGLESS JIBBER JABBER]

 Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext
 and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just
use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code
that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
*/
func Test11(t *testing.T) {
	ciphertext, cipher := randEncrypt([]byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))

	result := findCryptoMode(ciphertext)

	fmt.Printf("I think the mode was %s\n", result)

	assert.Equal(t, cipher, result)
}
