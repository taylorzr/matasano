package main

import (
	"crypto/aes"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"testing"
	"time"
	"unicode"

	"github.com/stretchr/testify/assert"
)

// TODO: Strip padding of \x04 in decryption functions

var (
	defaultKey    = []byte("YELLOW SUBMARINE")
	potentialKeys []byte
)

func init() {
	potentialKeys = make([]byte, 255)
	for i := 0; i < 255; i++ {
		potentialKeys[i] = byte(i)
	}
}

func findCryptoMode(ciphertext []byte) string {
	dupes := ecbDetect(ciphertext)

	if dupes {
		return "ECB"
	} else {
		return "CBC"
	}
}

func randEncrypt(plaintext []byte) ([]byte, string) {
	rand.Seed(time.Now().UTC().UnixNano())
	a, b := rand.Intn(5)+5, rand.Intn(5)+5
	key, startPad, endPad := randomKey(16), randomBytes(a), randomBytes(b)
	mode := []string{"ECB", "CBC"}[rand.Intn(2)]

	plaintext = append(startPad, plaintext...)
	plaintext = append(plaintext, endPad...)

	ciphertext := make([]byte, len(plaintext))
	switch mode {
	case "ECB":
		ciphertext = ecbEncrypt(plaintext, key)
	case "CBC":
		iv := randomBytes(16)
		ciphertext = cbcEncrypt(plaintext, key, iv)
	}

	return ciphertext, mode
}

func randomKey(length int) []byte {
	key := make([]byte, length)

	_, err := cryptoRand.Read(key)
	if err != nil {
		panic(err)
	}

	return key
}

func randomBytes(length int) []byte {
	bytes := make([]byte, length)

	_, err := cryptoRand.Read(bytes)
	if err != nil {
		panic(err)
	}

	return bytes
}

func ecbDetect(ciphertext []byte) bool {
	blocks := map[string]int{}

	for i := 0; i < len(ciphertext); i += 16 {
		block := ciphertext[i : i+16]
		blocks[string(block)] += 1
	}

	dupes := 0

	for _, count := range blocks {
		if count > 1 {
			dupes += (count - 1)
		}
	}

	return dupes > 0
}

func ecbEncrypt(plaintext, key []byte) []byte {
	ciph, _ := aes.NewCipher(key)

	plaintext = pad(plaintext, 16)
	ciphertext := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); i += 16 {
		ciph.Encrypt(ciphertext[i:i+16], plaintext[i:i+16])
	}

	return ciphertext
}

func ecbDecrypt(ciphertext, key []byte) []byte {
	ciph, _ := aes.NewCipher(key)

	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < len(ciphertext); i += 16 {
		ciph.Decrypt(plaintext[i:i+16], ciphertext[i:i+16])
	}

	return plaintext
}

func cbcEncrypt(plaintext, key, iv []byte) []byte {
	ciph, _ := aes.NewCipher(key)

	plaintext = pad(plaintext, 16)
	ciphertext := make([]byte, len(plaintext))
	previousCipherblock := iv

	for i := 0; i < len(plaintext); i += 16 {
		block := xor(previousCipherblock, plaintext[i:i+16])
		ciph.Encrypt(ciphertext[i:i+16], block)
		previousCipherblock = ciphertext[i : i+16]
	}

	return ciphertext
}

func cbcDecrypt(ciphertext, key, iv []byte) []byte {
	ciph, _ := aes.NewCipher(key)

	plaintext := make([]byte, 0, len(ciphertext))
	previousCipherblock := iv

	fmt.Printf("%#v\n", string(plaintext))

	for i := 0; i < len(ciphertext); i += 16 {
		block := make([]byte, 16)
		ciph.Decrypt(block, ciphertext[i:i+16])
		plaintext = append(plaintext, xor(previousCipherblock, block)...)
		previousCipherblock = ciphertext[i : i+16]
	}

	return plaintext
}

func pad(bytes []byte, blocksize int) []byte {
	padding := make([]byte, blocksize-(len(bytes)%blocksize))
	for i := range padding {
		padding[i] = '\x04'
	}
	return append(bytes, padding...)
}

func loadb64(t *testing.T, path string) []byte {
	data, err := ioutil.ReadFile(path)
	assert.Nil(t, err)
	ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	assert.Nil(t, err)
	return ciphertext
}

func decrypt(ciphertext, key []byte) []byte {
	bytes := make([]byte, len(ciphertext))

	for i, char := range ciphertext {
		bytes[i] = byte(char) ^ byte(key[i%len(key)])
	}

	return bytes
}

func findKey(block []byte) (byte, int, []byte) {
	var key byte
	var bestRank int
	var plaintext []byte

	for _, potentialKey := range potentialKeys {
		potentialPlaintext, rank := xorAndRank(potentialKey, block)

		if rank >= bestRank {
			key = potentialKey
			bestRank = rank
			plaintext = potentialPlaintext
		}
	}

	return key, bestRank, plaintext
}

func groupByKeyIndex(ciphertext []byte, keyLength int) [][]byte {
	bytesByKeyIndex := make([][]byte, keyLength)

	for i, cipherbyte := range ciphertext {
		bytes := bytesByKeyIndex[i%keyLength]
		if bytes == nil {
			bytes = []byte{}
		}
		bytesByKeyIndex[i%keyLength] = append(bytes, cipherbyte)
	}

	return bytesByKeyIndex
}

func findKeysize(ciphertext []byte) (int, float64) {
	bestKeysize := 0
	smallestDiff := math.MaxFloat64

	for keysize := 2; keysize <= 40; keysize++ {
		diff := 0.0
		// find the number of segments of keysize we can look at within the ciphertext then subtract 1
		// because we look at the next keysize of bytes in the loop
		iterations := (len(ciphertext) / keysize) - 1
		for i := 0; i <= iterations; i++ {
			a := ciphertext[i*keysize : (i+1)*keysize]
			b := ciphertext[(i+1)*keysize : (i+2)*keysize]
			// normalize by dividing the keysize because of course longer keysizes will have more
			// differences
			diff += float64(ham(a, b)) / float64(keysize)
		}
		// normalize the diff by diving the iterations because of course more interations will have more
		// differences
		diff = diff / float64(iterations)

		if diff < smallestDiff {
			bestKeysize = keysize
			smallestDiff = diff
		}
	}

	return bestKeysize, smallestDiff
}

// FIXME: Just copied this from the internets because I wasn't interested in understanding this
// part, understand me some day please
func ham(a, b []byte) int {
	diff := 0

	for i := 0; i < len(a); i++ {
		for j := 0; j < 8; j++ {
			mask := byte(1 << uint(j))
			if (a[i] & mask) != (b[i] & mask) {
				diff++
			}
		}
	}

	return diff
}

func xor(a, b []byte) []byte {
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
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
