/*

SPDX-Copyright: Copyright (c) Capital One Services, LLC
SPDX-License-Identifier: Apache-2.0
Copyright 2017 Capital One Services, LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.

*/

package ff1byte

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Test vectors taken from here: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/FF1samples.pdf

// As Golang's sub-tests were introduced in Go 1.7, but this package will work with Go 1.6+, so I'm keeping sub-tests in a separate branch for now.

type testVector struct {
	// Key and tweak are both hex-encoded strings
	key        string
	tweak      string
	plaintext  string
	ciphertext []byte
}

// Official NIST FF1 Test Vectors
var testVectors = []testVector{
	// AES-128
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"",
		"Hello, World!",
		[]byte{119, 7, 113, 82, 222, 162, 239, 241, 224, 65, 1, 161, 162},
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"39383736353433323130",
		"Hello, 世界！",
		[]byte{88, 236, 113, 120, 139, 247, 43, 136, 236, 101, 35, 42, 200, 254, 117, 66},
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"3737373770717273373737",
		"Testing...",
		[]byte{173, 3, 214, 157, 54, 220, 168, 232, 38, 233},
	},

	// AES-192
	{
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"",
		"Hello, World!",
		[]byte{82, 45, 128, 150, 140, 26, 69, 99, 0, 129, 142, 10, 107},
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"39383736353433323130",
		"Hello, 世界！",
		[]byte{55, 43, 119, 35, 139, 214, 108, 6, 151, 103, 182, 198, 121, 224, 231, 15},
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F",
		"3737373770717273373737",
		"Testing...",
		[]byte{43, 198, 140, 185, 20, 178, 212, 115, 128, 40},
	},

	// AES-256
	{
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"",
		"Hello, World!",
		[]byte{211, 28, 80, 55, 109, 185, 22, 250, 72, 129, 95, 34, 84},
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"39383736353433323130",
		"Hello, 世界！",
		[]byte{149, 31, 89, 135, 205, 12, 77, 117, 62, 17, 27, 42, 205, 237, 219, 59},
	},
	{
		"2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94",
		"3737373770717273373737",
		"Testing...",
		[]byte{137, 245, 53, 96, 225, 147, 240, 78, 53, 241},
	},
}

func TestEncrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(16, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			ciphertext, err := ff1.Encrypt([]byte(testVector.plaintext))
			if err != nil {
				t.Fatalf("%v", err)
			}

			if !bytes.Equal(ciphertext, testVector.ciphertext) {
				t.Fatalf("\nSample%d\n\nKey:\t\t%s\nTweak:\t\t%s\nPlaintext:\t%s\nCiphertext:\t%s\nExpected:\t%s", sampleNumber, testVector.key, testVector.tweak, testVector.plaintext, ciphertext, testVector.ciphertext)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		t.Run(fmt.Sprintf("Sample%d", sampleNumber), func(t *testing.T) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				t.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				t.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(16, key, tweak)
			if err != nil {
				t.Fatalf("Unable to create cipher: %v", err)
			}

			plaintext, err := ff1.Decrypt(testVector.ciphertext)
			if err != nil {
				t.Fatalf("%v", err)
			}

			if string(plaintext) != testVector.plaintext {
				t.Fatalf("\nSample%d\nKey:\t\t%s\nTweak:\t\t%s\nCiphertext:\t%s\nPlaintext:\t%s\nExpected:\t%s", sampleNumber, testVector.key, testVector.tweak, testVector.ciphertext, plaintext, testVector.plaintext)
			}
		})
	}
}

// These are for testing long inputs, which are not in the sandard test vectors
func TestLong(t *testing.T) {
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, err := hex.DecodeString("")

	// 16 is an arbitrary number for maxTlen
	ff1, err := NewCipher(16, key, tweak)
	if err != nil {
		t.Fatalf("Unable to create cipher: %v", err)
	}

	plaintext := "xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyal"
	plain := []byte(plaintext)

	ciphertext, err := ff1.Encrypt(plain)
	if err != nil {
		t.Fatalf("%v", err)
	}

	decrypted, err := ff1.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(plain, decrypted) {
		t.Fatalf("Long Decrypt Failed. \n Expected: %v \n Got: %v \n", plain, decrypted)
	}
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Encrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("")
	if err != nil {
		panic(err)
	}

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := NewCipher(8, key, tweak)
	if err != nil {
		panic(err)
	}

	original := []byte("Hello, World")

	// Call the encryption function on an example test vector
	ciphertext, err := FF1.Encrypt(original)
	if err != nil {
		panic(err)
	}

	fmt.Println(ciphertext)
	// Output: [24 248 199 117 158 133 225 104 8 235 62 45]
}

// Note: panic(err) is just used for example purposes.
func ExampleCipher_Decrypt() {
	// Key and tweak should be byte arrays. Put your key and tweak here.
	// To make it easier for demo purposes, decode from a hex string here.
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	if err != nil {
		panic(err)
	}
	tweak, err := hex.DecodeString("")
	if err != nil {
		panic(err)
	}

	// Create a new FF1 cipher "object"
	// 10 is the radix/base, and 8 is the tweak length.
	FF1, err := NewCipher(8, key, tweak)
	if err != nil {
		panic(err)
	}

	ciphertext := []byte{24, 248, 199, 117, 158, 133, 225, 104, 8, 235, 62, 45}

	plaintext, err := FF1.Decrypt(ciphertext)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(plaintext))
	// Output: Hello, World
}

func BenchmarkNewCipher(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			b.ResetTimer()

			// 16 is an arbitrary number for maxTlen
			for n := 0; n < b.N; n++ {
				NewCipher(16, key, tweak)
			}
		})
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(16, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff1.Encrypt([]byte(testVector.plaintext))
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for idx, testVector := range testVectors {
		sampleNumber := idx + 1
		b.Run(fmt.Sprintf("Sample%d", sampleNumber), func(b *testing.B) {
			key, err := hex.DecodeString(testVector.key)
			if err != nil {
				b.Fatalf("Unable to decode hex key: %v", testVector.key)
			}

			tweak, err := hex.DecodeString(testVector.tweak)
			if err != nil {
				b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
			}

			// 16 is an arbitrary number for maxTlen
			ff1, err := NewCipher(16, key, tweak)
			if err != nil {
				b.Fatalf("Unable to create cipher: %v", err)
			}

			b.ResetTimer()

			for n := 0; n < b.N; n++ {
				ff1.Decrypt(testVector.ciphertext)
			}
		})
	}
}

// This benchmark is for the end-to-end NewCipher, Encryption, Decryption process
// Similar to the examples
func BenchmarkE2ESample7(b *testing.B) {
	testVector := testVectors[6]
	key, err := hex.DecodeString(testVector.key)
	if err != nil {
		b.Fatalf("Unable to decode hex key: %v", testVector.key)
	}

	tweak, err := hex.DecodeString(testVector.tweak)
	if err != nil {
		b.Fatalf("Unable to decode tweak: %v", testVector.tweak)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		// 16 is an arbitrary number for maxTlen
		ff1, err := NewCipher(16, key, tweak)
		if err != nil {
			b.Fatalf("Unable to create cipher: %v", err)
		}

		ciphertext, err := ff1.Encrypt([]byte(testVector.plaintext))
		if err != nil {
			b.Fatalf("%v", err)
		}

		plaintext, err := ff1.Decrypt(ciphertext)
		if err != nil {
			b.Fatalf("%v", err)
		}

		_ = plaintext
	}
}

// BenchmarkEncryptLong is only for benchmarking the inner for loop code bath using a very large input to make d very large, making maxJ > 1
func BenchmarkEncryptLong(b *testing.B) {
	key, err := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")

	tweak, err := hex.DecodeString("")

	// 16 is an arbitrary number for maxTlen
	ff1, err := NewCipher(16, key, tweak)
	if err != nil {
		b.Fatalf("Unable to create cipher: %v", err)
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		ff1.Encrypt([]byte("xs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwdxs8a0azh2avyalyzuwd"))
	}
}
