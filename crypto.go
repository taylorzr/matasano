package main

import (
	"math"
	"unicode"
)

var potentialKeys []byte

func init() {
	potentialKeys = make([]byte, 255)
	for i := 0; i < 255; i++ {
		potentialKeys[i] = byte(i)
	}
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
