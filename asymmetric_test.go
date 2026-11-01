/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose/json"
)

func TestEd25519(t *testing.T) {
	_, err := newEd25519Signer("XYZ", nil)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	enc := new(edEncrypterVerifier)
	enc.publicKey = ed25519PublicKey
	err = enc.verifyPayload([]byte{}, []byte{}, "XYZ")
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	dec := new(edDecrypterSigner)
	dec.privateKey = ed25519PrivateKey
	_, err = dec.signPayload([]byte{}, "XYZ")
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	sig, err := dec.signPayload([]byte("This is a test"), "EdDSA")
	assert.NoError(t, err, "should not error trying to sign payload")
	if sig.Signature == nil {
		t.Error("Check the signature")
	}
	err = enc.verifyPayload([]byte("This is a test"), sig.Signature, "EdDSA")
	assert.NoError(t, err, "should not error trying to verify payload")

	err = enc.verifyPayload([]byte("This is test number 2"), sig.Signature, "EdDSA")
	assert.Error(t, err, "should not error trying to verify payload")
}

func TestInvalidAlgorithmsRSA(t *testing.T) {
	_, err := newRSARecipient("XYZ", nil)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	_, err = newRSASigner("XYZ", nil)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &rsaTestKey.PublicKey
	_, err = enc.encryptKey([]byte{}, "XYZ")
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	err = enc.verifyPayload([]byte{}, []byte{}, "XYZ")
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	dec := new(rsaDecrypterSigner)
	dec.privateKey = rsaTestKey
	_, err = dec.decrypt(make([]byte, 256), "XYZ", randomKeyGenerator{size: 16})
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	_, err = dec.signPayload([]byte{}, "XYZ")
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")
}

// RFC 7518 Section 3.5.
func TestRSAPSSVerifyRequiresSaltLengthEqualToHash(t *testing.T) {
	verifier := &rsaEncrypterVerifier{publicKey: &rsaTestKey.PublicKey}
	payload := []byte("payload")

	testCases := []struct {
		alg  SignatureAlgorithm
		hash crypto.Hash
	}{
		{PS256, crypto.SHA256},
		{PS384, crypto.SHA384},
		{PS512, crypto.SHA512},
	}

	for _, tc := range testCases {
		t.Run(string(tc.alg), func(t *testing.T) {
			hasher := tc.hash.New()
			hasher.Write(payload)
			hashed := hasher.Sum(nil)

			for _, saltLength := range []int{rsa.PSSSaltLengthAuto, 1, tc.hash.Size() - 1, tc.hash.Size() + 1} {
				sig, err := rsa.SignPSS(rand.Reader, rsaTestKey, tc.hash, hashed, &rsa.PSSOptions{SaltLength: saltLength})
				if err != nil {
					if fips140.Enabled() && saltLength > tc.hash.Size() {
						continue
					}

					t.Fatal(err)
				}

				// In FIPS 140 mode crypto/rsa caps the automatic salt length at the size of the hash.
				if fips140.Enabled() && saltLength == rsa.PSSSaltLengthAuto {
					err = verifier.verifyPayload(payload, sig, tc.alg)
					assert.NoError(t, err, "verifyPayload rejected the automatic salt length in FIPS 140 mode")

					continue
				}

				err = verifier.verifyPayload(payload, sig, tc.alg)
				assert.Error(t, err, "verifyPayload accepted a salt length of %d", saltLength)
			}

			sig, err := rsa.SignPSS(rand.Reader, rsaTestKey, tc.hash, hashed, &rsa.PSSOptions{SaltLength: tc.hash.Size()})
			require.NoError(t, err)

			err = verifier.verifyPayload(payload, sig, tc.alg)
			assert.NoError(t, err, "verifyPayload rejected a salt the size of the hash")
		})
	}
}

func TestECDHDecryptRejectsMalformedPrivateKey(t *testing.T) {
	keys := map[string]*ecdsa.PrivateKey{
		"Nil":      nil,
		"ZeroD":    {PublicKey: ecTestKey256.PublicKey, D: big.NewInt(0)},
		"DIsOrder": {PublicKey: ecTestKey256.PublicKey, D: elliptic.P256().Params().N},
		"NilD":     {PublicKey: ecTestKey256.PublicKey},
		"NilCurve": {PublicKey: ecdsa.PublicKey{X: ecTestKey256.X, Y: ecTestKey256.Y}, D: ecTestKey256.D},
	}

	for _, alg := range []KeyAlgorithm{ECDH_ES, ECDH_ES_A128KW} {
		encrypter, err := NewEncrypter(A128GCM, Recipient{Algorithm: alg, Key: &ecTestKey256.PublicKey}, nil)
		require.NoError(t, err)

		obj, err := encrypter.Encrypt([]byte("payload"))
		require.NoError(t, err)

		for name, key := range keys {
			t.Run(string(alg)+"/"+name, func(t *testing.T) {
				_, err := obj.Decrypt(key)
				assert.Error(t, err, "Decrypt accepted a malformed private key")
			})
		}
	}
}

func TestNewEncrypterRejectsECDHESToAPointNotOnTheCurve(t *testing.T) {
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}

	for _, alg := range []KeyAlgorithm{ECDH_ES, ECDH_ES_A128KW} {
		_, err := NewEncrypter(A128GCM, Recipient{Algorithm: alg, Key: key}, nil)
		assert.Error(t, err, "NewEncrypter(%s) accepted a public key not on the curve", alg)
	}
}

// RFC 8017 Section 3.1.
func TestRSAKeyWithInvalidExponentIsRefusedOnEveryPath(t *testing.T) {
	for _, e := range []int{1, 2, 4, 65536} {
		t.Run(fmt.Sprint(e), func(t *testing.T) {
			priv := *rsaTestKey
			priv.PublicKey = rsa.PublicKey{N: rsaTestKey.N, E: e}

			if signer, err := NewSigner(SigningKey{Algorithm: RS256, Key: &priv}, nil); err == nil {
				if _, err = signer.Sign([]byte("payload")); !errors.Is(err, errInvalidRSAExponent) {
					t.Errorf("Sign: got %v, want %v", err, errInvalidRSAExponent)
				}
			} else if !errors.Is(err, errInvalidRSAExponent) {
				t.Errorf("NewSigner: got %v, want %v", err, errInvalidRSAExponent)
			}

			if encrypter, err := NewEncrypter(A128GCM, Recipient{Algorithm: RSA_OAEP_256, Key: &priv.PublicKey}, nil); err == nil {
				if _, err = encrypter.Encrypt([]byte("payload")); !errors.Is(err, errInvalidRSAExponent) {
					t.Errorf("Encrypt: got %v, want %v", err, errInvalidRSAExponent)
				}
			} else if !errors.Is(err, errInvalidRSAExponent) {
				t.Errorf("NewEncrypter: got %v, want %v", err, errInvalidRSAExponent)
			}

			verifier := rsaEncrypterVerifier{publicKey: &priv.PublicKey}
			if err := verifier.verifyPayload([]byte("payload"), make([]byte, 256), RS256); !errors.Is(err, errInvalidRSAExponent) {
				t.Errorf("verifyPayload: got %v, want %v", err, errInvalidRSAExponent)
			}

			decrypter := rsaDecrypterSigner{privateKey: &priv}
			if _, err := decrypter.decrypt(make([]byte, 256), RSA_OAEP_256, randomKeyGenerator{size: 16}); !errors.Is(err, errInvalidRSAExponent) {
				t.Errorf("decrypt: got %v, want %v", err, errInvalidRSAExponent)
			}
		})
	}
}

type failingKeyGenerator struct{}

func (ctx failingKeyGenerator) keySize() int {
	return 0
}

func (ctx failingKeyGenerator) genKey() ([]byte, rawHeader, error) {
	return nil, rawHeader{}, errors.New("failed to generate key")
}

func TestPKCSKeyGeneratorFailure(t *testing.T) {
	dec := new(rsaDecrypterSigner)
	dec.privateKey = rsaTestKey
	generator := failingKeyGenerator{}
	_, err := dec.decrypt(make([]byte, 256), RSA1_5, generator)
	assert.ErrorIs(t, err, ErrCryptoFailure, "should return error on invalid algorithm")
}

func TestInvalidAlgorithmsEC(t *testing.T) {
	_, err := newECDHRecipient("XYZ", nil)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	_, err = newECDSASigner("XYZ", nil)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")

	enc := new(ecEncrypterVerifier)
	enc.publicKey = &ecTestKey256.PublicKey
	_, err = enc.encryptKey([]byte{}, "XYZ")
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should return error on invalid algorithm")
}

func TestInvalidECKeyGen(t *testing.T) {
	gen := ecKeyGenerator{
		size:      16,
		algID:     "A128GCM",
		publicKey: &ecTestKey256.PublicKey,
	}

	assert.Equal(t, 16, gen.keySize(), "ec key generator reported incorrect key size")

	_, _, err := gen.genKey()
	assert.NoError(t, err, "ec key generator failed to generate key")
}

func TestInvalidECDecrypt(t *testing.T) {
	dec := ecDecrypterSigner{
		privateKey: ecTestKey256,
	}

	generator := randomKeyGenerator{size: 16}

	recipient := recipientInfo{
		// decryptKey will error out before the contents here matter
		encryptedKey: []byte("not used"),
	}
	// Missing epk header
	headers := rawHeader{}

	require.NoError(t, headers.set(headerAlgorithm, ECDH_ES))

	want := "go-jose/go-jose: missing epk header"
	_, err := dec.decryptKey(headers, &recipient, generator)
	if err == nil {
		t.Error("ec decrypter accepted object with missing epk header")
	} else if err.Error() != want {
		t.Errorf("decryptKey with missing epk header: got %q, want %q", err, want)
	}

	// Invalid epk header
	invalid := json.RawMessage("invalid")
	headers["epk"] = &invalid

	want = "go-jose/go-jose: invalid epk header"
	_, err = dec.decryptKey(headers, &recipient, generator)
	if err == nil {
		t.Error("ec decrypter accepted object with invalid epk header")
	} else if err.Error() != want {
		t.Errorf("decryptKey with invalid epk header: got %q, want %q", err, want)
	}
}

func TestDecryptWithIncorrectSize(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	payload := make([]byte, 254)
	_, err = dec.decrypt(payload, RSA1_5, keygen)
	assert.Error(t, err, "Invalid payload size should return error")

	payload = make([]byte, 257)
	_, err = dec.decrypt(payload, RSA1_5, keygen)
	assert.Error(t, err, "Invalid payload size should return error")
}

func TestPKCSDecryptNeverFails(t *testing.T) {
	// We don't want RSA-PKCS1 v1.5 decryption to ever fail, in order to prevent
	// side-channel timing attacks (Bleichenbacher attack in particular).
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Error(err)
		return
	}

	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	for i := 1; i < 50; i++ {
		payload := make([]byte, 256)
		_, err := io.ReadFull(rand.Reader, payload)
		if err != nil {
			t.Error("Unable to get random data:", err)
			return
		}
		_, err = dec.decrypt(payload, RSA1_5, keygen)
		if err != nil {
			t.Error("PKCS1v1.5 decrypt should never fail:", err)
			return
		}
	}
}

func BenchmarkPKCSDecryptWithValidPayloads(b *testing.B) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &priv.PublicKey
	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(32)

	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext := make([]byte, 32)
		_, err = io.ReadFull(rand.Reader, plaintext)
		if err != nil {
			panic(err)
		}

		ciphertext, err := enc.encrypt(plaintext, RSA1_5)
		if err != nil {
			panic(err)
		}

		keygen := randomKeyGenerator{
			size: aes.keySize(),
		}

		b.StartTimer()
		_, err = dec.decrypt(ciphertext, RSA1_5, keygen)
		b.StopTimer()
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkPKCSDecryptWithInvalidPayloads(b *testing.B) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	enc := new(rsaEncrypterVerifier)
	enc.publicKey = &priv.PublicKey
	dec := new(rsaDecrypterSigner)
	dec.privateKey = priv
	aes := newAESGCM(16)

	keygen := randomKeyGenerator{
		size: aes.keySize(),
	}

	b.StopTimer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plaintext := make([]byte, 16)
		_, err = io.ReadFull(rand.Reader, plaintext)
		if err != nil {
			panic(err)
		}

		ciphertext, err := enc.encrypt(plaintext, RSA1_5)
		if err != nil {
			panic(err)
		}

		// Do some simple scrambling
		ciphertext[128] ^= 0xFF

		b.StartTimer()
		_, err = dec.decrypt(ciphertext, RSA1_5, keygen)
		b.StopTimer()
		if err != nil {
			panic(err)
		}
	}
}

func TestInvalidEllipticCurve(t *testing.T) {
	signer256 := ecDecrypterSigner{privateKey: ecTestKey256}
	signer384 := ecDecrypterSigner{privateKey: ecTestKey384}
	signer521 := ecDecrypterSigner{privateKey: ecTestKey521}

	_, err := signer256.signPayload([]byte{}, ES384)
	assert.Error(t, err, "should not generate ES384 signature with P-256 key")
	_, err = signer256.signPayload([]byte{}, ES512)
	assert.Error(t, err, "should not generate ES512 signature with P-256 key")
	_, err = signer384.signPayload([]byte{}, ES256)
	assert.Error(t, err, "should not generate ES256 signature with P-384 key")
	_, err = signer384.signPayload([]byte{}, ES512)
	assert.Error(t, err, "should not generate ES512 signature with P-384 key")
	_, err = signer521.signPayload([]byte{}, ES256)
	assert.Error(t, err, "should not generate ES256 signature with P-521 key")
	_, err = signer521.signPayload([]byte{}, ES384)
	assert.Error(t, err, "should not generate ES384 signature with P-521 key")
}

func TestInvalidECPublicKey(t *testing.T) {
	// Invalid key
	invalid := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     fromBase64Int("MTEx"),
			Y:     fromBase64Int("MTEx"),
		},
		D: fromBase64Int("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"),
	}

	recipient := recipientInfo{
		// encryptedKey must be non-empty to pass initial checks, but the actual
		// bytes don't matter because we'll error out before using them.
		encryptedKey: []byte("not used"),
	}

	headers := rawHeader{}

	require.NoError(t, headers.set(headerAlgorithm, ECDH_ES))

	headers[headerEPK] = makeRawMessage([]byte(`{"kty":"EC","crv":"P-256","x":"` +
		newFixedSizeBuffer(invalid.X.Bytes(), 32).base64() + `","y":"` +
		newFixedSizeBuffer(invalid.Y.Bytes(), 32).base64() + `"}`))

	dec := ecDecrypterSigner{
		privateKey: ecTestKey256,
	}

	_, err := dec.decryptKey(headers, &recipient, randomKeyGenerator{size: 16})
	require.Error(t, err, "decrypter accepted JWS with invalid ECDH public key")

	want := "go-jose/go-jose: invalid epk header"
	assert.Equal(t, want, err.Error(), "decryptKey with invalid ECDH public key: got %q, want %q", err, want)
}

func TestInvalidAlgorithmEC(t *testing.T) {
	err := ecEncrypterVerifier{publicKey: &ecTestKey256.PublicKey}.verifyPayload([]byte{}, []byte{}, "XYZ")
	require.ErrorIs(t, err, ErrUnsupportedAlgorithm, "should not accept invalid/unsupported algorithm")
}

func TestECDHDecryptKeyRejectsEPKOnAnotherCurve(t *testing.T) {
	testCases := []struct {
		name string
		epk  *ecdsa.PublicKey
		err  string
	}{
		{"ShouldAcceptMatchingCurve", &ecTestKey256.PublicKey, ""},
		{"ShouldRejectLargerCurve", &ecTestKey384.PublicKey, "go-jose/go-jose: invalid public key in epk header"},
		{"ShouldRejectSmallerCurve", &ecTestKey521.PublicKey, "go-jose/go-jose: invalid public key in epk header"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := rawHeader{}

			require.NoError(t, headers.set(headerEPK, &JSONWebKey{Key: tc.epk}))
			require.NoError(t, headers.set(headerAlgorithm, ECDH_ES))

			ctx := ecDecrypterSigner{privateKey: ecTestKey256}

			_, err := ctx.decryptKey(headers, &recipientInfo{}, randomKeyGenerator{size: 16})

			if tc.err == "" {
				require.NoError(t, err)

				return
			}

			require.Error(t, err, "accepted an epk header on another curve")

			assert.Equal(t, tc.err, err.Error())
		})
	}
}

// RFC 7518 Section 3.4 pairs each ECDSA algorithm with exactly one curve.
func TestECDSAVerifyRejectsWrongCurveForAlgorithm(t *testing.T) {
	testCases := []struct {
		alg       SignatureAlgorithm
		curve     elliptic.Curve
		hash      crypto.Hash
		sigOctets int
	}{
		{ES384, elliptic.P256(), crypto.SHA384, 48},
		{ES512, elliptic.P256(), crypto.SHA512, 66},
		{ES512, elliptic.P384(), crypto.SHA512, 66},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_with_%s", tc.alg, tc.curve.Params().Name), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			payload := []byte("payload")
			hasher := tc.hash.New()
			hasher.Write(payload)

			r, s, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
			require.NoError(t, err)

			signature := make([]byte, 2*tc.sigOctets)
			r.FillBytes(signature[:tc.sigOctets])
			s.FillBytes(signature[tc.sigOctets:])

			verifier := &ecEncrypterVerifier{publicKey: &key.PublicKey}
			assert.Error(t, verifier.verifyPayload(payload, signature, tc.alg))
		})
	}
}

// The matching curve must still verify, and each algorithm must still reject a
// signature made over the wrong digest on the right curve.
func TestECDSAVerifyAcceptsMatchingCurve(t *testing.T) {
	testCases := []struct {
		alg   SignatureAlgorithm
		curve elliptic.Curve
	}{
		{ES256, elliptic.P256()},
		{ES384, elliptic.P384()},
		{ES512, elliptic.P521()},
	}

	for _, tc := range testCases {
		t.Run(string(tc.alg), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			signer := &ecDecrypterSigner{privateKey: key}
			payload := []byte("payload")

			sig, err := signer.signPayload(payload, tc.alg)
			require.NoError(t, err, "signPayload")

			verifier := &ecEncrypterVerifier{publicKey: &key.PublicKey}
			err = verifier.verifyPayload(payload, sig.Signature, tc.alg)
			assert.NoError(t, err, "verifyPayload rejected a matching %s signature", tc.alg)

			err = verifier.verifyPayload([]byte("other"), sig.Signature, tc.alg)
			assert.Error(t, err, "verifyPayload accepted a signature over a different payload")
		})
	}
}

func TestECDSAVerifyRejectsNilKey(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("verifyPayload panicked on a nil public key: %v", r)
		}
	}()

	verifier := &ecEncrypterVerifier{publicKey: nil}
	err := verifier.verifyPayload([]byte("payload"), make([]byte, 64), ES256)
	assert.Error(t, err, "verifyPayload accepted a nil public key, want an error")
}

// RFC 7518 Sections 3.3, 3.5, 4.2 and 4.3 each require a modulus of at least
// 2048 bits.
func TestRSARejectsUndersizedKeys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	signer := &rsaDecrypterSigner{privateKey: small}
	verifier := &rsaEncrypterVerifier{publicKey: &small.PublicKey}

	for _, alg := range []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512} {
		if _, err = signer.signPayload([]byte("payload"), alg); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("signPayload(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}

		if err = verifier.verifyPayload([]byte("payload"), make([]byte, 128), alg); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("verifyPayload(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}
	}

	for _, alg := range []KeyAlgorithm{RSA1_5, RSA_OAEP, RSA_OAEP_256} {
		if _, err = verifier.encrypt(make([]byte, 32), alg); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("encrypt(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}

		if _, err = signer.decrypt(make([]byte, 128), alg, randomKeyGenerator{size: 32}); !errors.Is(err, ErrInvalidKeySize) {
			t.Errorf("decrypt(%s) with a 1024 bit key: got %v, want %v", alg, err, ErrInvalidKeySize)
		}
	}
}

func TestRSAAcceptsMinimumKeySize(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, minRSAKeyBits)
	require.NoError(t, err)

	signer := &rsaDecrypterSigner{privateKey: key}
	verifier := &rsaEncrypterVerifier{publicKey: &key.PublicKey}

	for _, alg := range []SignatureAlgorithm{RS256, PS512} {
		sig, err := signer.signPayload([]byte("payload"), alg)
		require.NoError(t, err, "signPayload(%s) with a %d bit key", alg, minRSAKeyBits)

		err = verifier.verifyPayload([]byte("payload"), sig.Signature, alg)
		assert.NoError(t, err, "verifyPayload(%s) rejected a conforming key", alg)
	}
}

func TestRSARejectsNilKeys(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked on a nil key: %v", r)
		}
	}()

	verifier := &rsaEncrypterVerifier{publicKey: nil}
	err := verifier.verifyPayload([]byte("payload"), make([]byte, 256), RS256)
	assert.Error(t, err, "verifyPayload accepted a nil public key, want an error")

	signer := &rsaDecrypterSigner{privateKey: nil}
	_, err = signer.signPayload([]byte("payload"), RS256)
	assert.Error(t, err, "signPayload accepted a nil private key, want an error")
}

// A low-order Ed25519 public key admits a single signature that verifies for
// every message: verification reduces to [S]B = R + [k]A, and for the identity
// point [k]A is the identity whatever the message hashes to, so R = identity
// with S = 0 satisfies it universally. The fork screens for these keys when
// parsing a JWK, but Verify also accepts a raw ed25519.PublicKey, and that path
// reached crypto/ed25519 unscreened.
func TestEd25519VerifyRejectsLowOrderKey(t *testing.T) {
	publicKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	publicKey[0] = 0x01 // identity point

	signature := make([]byte, ed25519.SignatureSize)
	signature[0] = 0x01 // R = identity, S = 0

	// Precondition: crypto/ed25519 itself accepts this, for any message.
	require.True(t, ed25519.Verify(publicKey, []byte("first message"), signature), "precondition failed: crypto/ed25519 rejected the forgery")

	verifier := &edEncrypterVerifier{publicKey: publicKey}

	for _, message := range []string{"first message", "a completely different message"} {
		err := verifier.verifyPayload([]byte(message), signature, EdDSA)
		assert.Error(t, err, "verifyPayload accepted a low-order key for %q, want an error", message)
	}
}

// Wrong-length keys panicked inside crypto/ed25519 instead of erroring.
func TestEd25519RejectsMalformedKeys(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked on a malformed key: %v", r)
		}
	}()

	for _, publicKey := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 33)} {
		verifier := &edEncrypterVerifier{publicKey: publicKey}
		err := verifier.verifyPayload([]byte("payload"), make([]byte, ed25519.SignatureSize), EdDSA)
		assert.Error(t, err, "verifyPayload accepted a %d byte public key, want an error", len(publicKey))
	}

	for _, privateKey := range []ed25519.PrivateKey{nil, make([]byte, 63), make([]byte, 65)} {
		signer := &edDecrypterSigner{privateKey: privateKey}
		_, err := signer.signPayload([]byte("payload"), EdDSA)
		assert.Error(t, err, "signPayload accepted a %d byte private key, want an error", len(privateKey))
	}
}

// A genuine key must still round-trip, and a signature over another payload
// must still be rejected.
func TestEd25519AcceptsValidKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := &edDecrypterSigner{privateKey: private}
	verifier := &edEncrypterVerifier{publicKey: public}

	sig, err := signer.signPayload([]byte("payload"), EdDSA)
	require.NoError(t, err, "signPayload")

	err = verifier.verifyPayload([]byte("payload"), sig.Signature, EdDSA)
	assert.NoError(t, err, "verifyPayload rejected a valid signature")

	err = verifier.verifyPayload([]byte("other"), sig.Signature, EdDSA)
	assert.Error(t, err, "verifyPayload accepted a signature over a different payload")
}

// RFC 9864 Section 2.2 registers "Ed25519" as the fully-specified identifier for
// the parameter set that RFC 8037's polymorphic "EdDSA" leaves unstated, and
// Section 4.1.2 deprecates "EdDSA" in the registry. Both name the same
// operation, so a signature made under one identifier verifies under the other.
func TestEd25519FullySpecifiedAlgorithm(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := &edDecrypterSigner{privateKey: private}
	verifier := &edEncrypterVerifier{publicKey: public}

	algorithms := []SignatureAlgorithm{EdDSA, Ed25519}

	for _, signAlg := range algorithms {
		sig, err := signer.signPayload([]byte("payload"), signAlg)
		require.NoError(t, err, "signPayload(%s)", signAlg)

		for _, verifyAlg := range algorithms {
			err = verifier.verifyPayload([]byte("payload"), sig.Signature, verifyAlg)
			assert.NoError(t, err, "signed under %s, verifying under %s", signAlg, verifyAlg)
		}
	}

	// An unrelated algorithm must still be refused.
	if err = verifier.verifyPayload([]byte("payload"), make([]byte, 64), ES256); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("verifyPayload(ES256) = %v, want %v", err, ErrUnsupportedAlgorithm)
	}
}

func TestEd25519AlgorithmReachesTheHeader(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, alg := range []SignatureAlgorithm{EdDSA, Ed25519} {
		signer, err := NewSigner(SigningKey{Algorithm: alg, Key: private}, nil)
		require.NoError(t, err, "NewSigner(%s)", alg)

		obj, err := signer.Sign([]byte("payload"))
		require.NoError(t, err, "Sign(%s)", alg)

		serialized, err := obj.CompactSerialize()
		require.NoError(t, err, "CompactSerialize(%s)", alg)

		parsed, err := ParseSignedCompact(serialized, []SignatureAlgorithm{alg})
		require.NoError(t, err, "ParseSignedCompact(%s)", alg)

		if got := parsed.Signatures[0].Header.Algorithm; got != string(alg) {
			t.Errorf("header alg = %q, want %q", got, alg)
		}

		other := EdDSA
		if alg == EdDSA {
			other = Ed25519
		}

		_, err = ParseSignedCompact(serialized, []SignatureAlgorithm{other})
		assert.Error(t, err, "a %s token was accepted by a parse restricted to %s", alg, other)
	}
}

// RFC 8017 Section 7.2.2 sizes an RSAES-PKCS1-v1_5 ciphertext at the octet length of the modulus. The expected
// length was previously taken as the bit length divided by eight, rounded down, so for a modulus whose bit length is
// not a multiple of eight every genuine RSA1_5 message was rejected as the wrong size.
func TestRSA1_5DecryptsWithModulusNotAMultipleOfEightBits(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2052)
	require.NoError(t, err)

	if key.N.BitLen()%8 == 0 {
		t.Fatalf("expected a modulus whose bit length is not a multiple of 8, got %d bits", key.N.BitLen())
	}

	encrypter, err := NewEncrypter(A128GCM, Recipient{Algorithm: RSA1_5, Key: &key.PublicKey}, nil)
	require.NoError(t, err)

	obj, err := encrypter.Encrypt([]byte("hello world"))
	require.NoError(t, err)

	plaintext, err := obj.Decrypt(key)
	require.NoError(t, err)

	require.Equal(t, "hello world", string(plaintext), "decrypted %q, want %q", plaintext, "hello world")
}

// An ecdsa key without a curve does not match any algorithm, and was already rejected for that. Building the error
// dereferenced the missing curve to describe it, so signing or verifying with such a key panicked instead.
func TestECDSAKeyWithoutCurveReturnsError(t *testing.T) {
	t.Run("ShouldNotPanicWhenSigning", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: &ecdsa.PrivateKey{}}, nil)
		if err != nil {
			return
		}

		_, err = signer.Sign([]byte("payload"))
		require.Error(t, err, "signed with an ecdsa key without a curve")
	})

	t.Run("ShouldNotPanicWhenVerifying", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: ecTestKey256}, nil)
		require.NoError(t, err)

		obj, err := signer.Sign([]byte("payload"))
		require.NoError(t, err)

		_, err = obj.Verify(&ecdsa.PublicKey{})
		require.Error(t, err, "verified with an ecdsa key without a curve")
	})

	t.Run("ShouldNotPanicWhenSigningWithTypedNilCurve", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: (*elliptic.CurveParams)(nil)}}}, nil)
		if err != nil {
			return
		}

		_, err = signer.Sign([]byte("payload"))
		require.Error(t, err, "signed with an ecdsa key with a typed nil curve")
	})

	t.Run("ShouldNotPanicWhenVerifyingWithTypedNilCurve", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: ecTestKey256}, nil)
		require.NoError(t, err)

		obj, err := signer.Sign([]byte("payload"))
		require.NoError(t, err)

		_, err = obj.Verify(&ecdsa.PublicKey{Curve: (*elliptic.CurveParams)(nil)})
		require.Error(t, err, "verified with an ecdsa key with a typed nil curve")
	})
}

// The curve is named rather than sized in the error, since a different curve of the same size is rejected as well.
func TestECDSACurveMismatchNamesTheCurve(t *testing.T) {
	lookalike := &ecdsa.PublicKey{Curve: elliptic.P256().Params(), X: ecTestKey256.X, Y: ecTestKey256.Y}
	signature := make([]byte, 64)

	err := (ecEncrypterVerifier{publicKey: lookalike}).verifyPayload([]byte("payload"), signature, ES256)
	if err == nil || !strings.Contains(err.Error(), "ES256 requires the P-256 curve") {
		t.Errorf("verifyPayload() error = %v, want it to name the P-256 curve", err)
	}

	_, err = (ecDecrypterSigner{privateKey: ecTestKey256}).signPayload([]byte("payload"), ES384)
	if err == nil || !strings.Contains(err.Error(), "ES384 requires the P-384 curve") {
		t.Errorf("signPayload() error = %v, want it to name the P-384 curve", err)
	}
}

func TestECDSAKeyWithoutCoordinatesIsAnError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	public := &ecdsa.PublicKey{Curve: elliptic.P256()}
	private := &ecdsa.PrivateKey{PublicKey: *public, D: key.D}

	t.Run("NewEncrypter", func(t *testing.T) {
		_, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: public}, nil)
		assert.Error(t, err)
	})

	t.Run("Verify", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: key}, nil)
		require.NoError(t, err)

		object, err := signer.Sign([]byte("payload"))
		require.NoError(t, err)

		_, err = object.Verify(public)
		assert.Error(t, err)
	})

	t.Run("Decrypt", func(t *testing.T) {
		encrypter, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: &key.PublicKey}, nil)
		require.NoError(t, err)

		object, err := encrypter.Encrypt([]byte("payload"))
		require.NoError(t, err)

		_, err = object.Decrypt(private)
		assert.Error(t, err)
	})
}
