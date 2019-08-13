package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
	"unicode"

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

func xorAndRank(key byte, bytes []byte) ([]byte, int) {
	ranking := map[rune]int{
		'e': 13,
		't': 12,
		'a': 11,
		'o': 10,
		'i': 9,
		'n': 8,
		' ': 7,
		's': 6,
		'h': 5,
		'r': 4,
		'd': 3,
		'l': 2,
		'u': 1,
	}

	potentialBytes := make([]byte, len(bytes))
	rank := 0

	for i := range bytes {
		potentialByte := bytes[i] ^ key
		potentialBytes[i] = potentialByte
		rank += ranking[unicode.ToLower(rune(potentialByte))]
		// rank += ranking[rune(potentialByte)]
	}

	return potentialBytes, rank
}

func Test3(t *testing.T) {
	bytes, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	assert.Nil(t, err)

	potentialKeys := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	var bestRank int
	var bestKey byte
	var bestPhrase string

	for _, key := range potentialKeys {
		potentialBytes, rank := xorAndRank(key, bytes)

		if rank >= bestRank {
			bestRank = rank
			bestKey = key
			bestPhrase = string(potentialBytes)
		}
	}

	fmt.Printf("Key: %c Rank: %d		%s\n", bestKey, bestRank, bestPhrase)

	assert.Equal(t, bestPhrase, "Cooking MC's like a pound of bacon")
}

func Test4(t *testing.T) {
	bytes, err := ioutil.ReadFile("4.txt")
	assert.Nil(t, err)
	lines := strings.Split(string(bytes), "\n")

	potentialKeys := make([]byte, 255)
	for i := 0; i < 255; i++ {
		potentialKeys[i] = byte(i)
	}

	var bestRank int
	var bestKey byte
	var bestLine int
	var bestPhrase string

	for i, line := range lines {
		bytes, err := hex.DecodeString(line)
		assert.Nil(t, err)

		for _, key := range potentialKeys {
			potentialBytes, rank := xorAndRank(key, bytes)

			if rank >= bestRank {
				bestRank = rank
				bestKey = key
				bestLine = i
				bestPhrase = string(potentialBytes)
			}
		}
	}

	fmt.Printf("Key: %c Line: %d Rank: %d		%s\n", bestKey, bestLine+1, bestRank, bestPhrase)

	if !strings.HasPrefix(bestPhrase, "Now that the party is jumping") {
		t.Errorf("Expected the party to be jumping, but got '%s'", bestPhrase)
	}
}

func Test5(t *testing.T) {
	key := "ICE"
	phrase := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	bytes := make([]byte, len(phrase))

	for i, char := range phrase {
		k := key[i%3]
		bytes[i] = byte(char) ^ byte(k)
	}

	assert.Equal(t, hex.EncodeToString(bytes), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
}
