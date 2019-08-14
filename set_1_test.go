package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test1(t *testing.T) {
	encoded := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	bytes, err := hex.DecodeString(encoded)

	assert.Nil(t, err)

	fmt.Println(string(bytes))

	result := base64.StdEncoding.EncodeToString(bytes)

	if result != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Error("Nope")
	}
}

func Test2(t *testing.T) {
	a, err := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	assert.Nil(t, err)
	b, err := hex.DecodeString("686974207468652062756c6c277320657965")
	assert.Nil(t, err)

	c := make([]byte, len(a))

	for i := range a {
		c[i] = a[i] ^ b[i]
	}

	fmt.Println(string(c))

	result := hex.EncodeToString(c)

	if result != "746865206b696420646f6e277420706c6179" {
		t.Error("Nope")
	}
}

func Test3(t *testing.T) {
	bytes, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	assert.Nil(t, err)

	key, rank, plaintext := findKey(bytes)

	fmt.Printf("Key: %c Rank: %d		%s\n", key, rank, plaintext)

	assert.Equal(t, "Cooking MC's like a pound of bacon", string(plaintext))
}

func Test4(t *testing.T) {
	bytes, err := ioutil.ReadFile("4.txt")
	assert.Nil(t, err)
	lines := strings.Split(string(bytes), "\n")

	var lineNumber int
	var key byte
	var bestRank int
	var plaintext []byte

	for i, line := range lines {
		bytes, err := hex.DecodeString(line)
		assert.Nil(t, err)

		potentialKey, rank, potentialPlaintext := findKey(bytes)

		if rank >= bestRank {
			lineNumber = i
			key = potentialKey
			bestRank = rank
			plaintext = potentialPlaintext
		}
	}

	fmt.Printf("Key: %c Line: %d Rank: %d		%s\n", key, lineNumber+1, bestRank, plaintext)

	assert.True(t, strings.HasPrefix(string(plaintext), "Now that the party is jumping"))
}

func Test5(t *testing.T) {
	key := []byte("ICE")
	phrase := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)

	plaintext := decrypt(phrase, key)

	assert.Equal(t, hex.EncodeToString(plaintext), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
}

// Check ham
func Test6a(t *testing.T) {
	result := ham([]byte("this is a test"), []byte("wokka wokka!!!"))

	assert.Equal(t, result, 37)
}

// Find key length
func Test6b(t *testing.T) {
	ciphertext := loadb64(t, "6.txt")

	keysize, diff := findKeysize(ciphertext)

	fmt.Printf("Keysize: %d	Diff: %f\n", keysize, diff)

	assert.Equal(t, keysize, 29)
}

// Find key
func Test6c(t *testing.T) {
	ciphertext := loadb64(t, "6.txt")

	bytesByKeyIndex := groupByKeyIndex(ciphertext, 29)

	key := make([]byte, 29)

	for i, bytes := range bytesByKeyIndex {
		blockKey, _, _ := findKey(bytes)
		key[i] = blockKey
	}

	fmt.Printf("Key: %s\n", key)

	assert.Equal(t, "Terminator X: Bring the noise", string(key))
}

// Decrypt
func Test6d(t *testing.T) {
	ciphertext := loadb64(t, "6.txt")

	plaintext := decrypt(ciphertext, []byte("Terminator X: Bring the noise"))

	fmt.Println(string(plaintext))
}

// ECB encryption
func Test7(t *testing.T) {
	ciphertext := loadb64(t, "7.txt")

	cipher, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += 16 {
		cipher.Decrypt(plaintext[i:i+16], ciphertext[i:i+16])
	}

	assert.True(t, strings.HasPrefix(string(plaintext), lyrics))
}

func Test8(t *testing.T) {
	data, err := ioutil.ReadFile("8.txt")
	assert.Nil(t, err)

	bestRank := 0
	bestLine := 0

	for lineNumber, line := range strings.Split(string(data), "\n") {
		blocks := map[string]int{}

		for i := 0; i < len(line); i += 16 {
			block := line[i : i+16]
			blocks[string(block)] += 1
		}

		rank := 0

		for _, count := range blocks {
			if count > 1 {
				rank += (count - 1)
			}
		}

		fmt.Printf("Rank: %d	Line: %d\n", rank, lineNumber)

		if rank >= bestRank {
			bestRank = rank
			bestLine = lineNumber + 1
		}
	}

	fmt.Printf("Best rank: %d	Line: %d\n", bestRank, bestLine)
	// try to see if any blocks repeat

	// if that doesn't work

	// try ham diff across blocks, and select smallest diff
}
