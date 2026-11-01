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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math"
	"math/big"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose/json"
)

type staticNonceSource string

func (sns staticNonceSource) Nonce() (string, error) {
	return string(sns), nil
}

func RoundtripJWS(sigAlg SignatureAlgorithm, serializer func(*JSONWebSignature) (string, error), corrupter func(*JSONWebSignature), signingKey any, verificationKey any, nonce string) error {
	opts := &SignerOptions{}
	if nonce != "" {
		opts.NonceSource = staticNonceSource(nonce)
	}

	signer, err := NewSigner(SigningKey{Algorithm: sigAlg, Key: signingKey}, opts)
	if err != nil {
		return fmt.Errorf("error on new signer: %s", err)
	}

	input := []byte("Lorem ipsum dolor sit amet")
	obj, err := signer.Sign(input)
	if err != nil {
		return fmt.Errorf("error on sign: %s", err)
	}

	msg, err := serializer(obj)
	if err != nil {
		return fmt.Errorf("error on serialize: %s", err)
	}

	obj, err = ParseSigned(msg, []SignatureAlgorithm{sigAlg})
	if err != nil {
		return fmt.Errorf("error on parse: %s", err)
	}

	// (Maybe) mangle the object
	corrupter(obj)

	output, err := obj.Verify(verificationKey)
	if err != nil {
		return fmt.Errorf("error on verify: %s", err)
	}

	// Check that verify works with embedded keys (if present)
	for i, sig := range obj.Signatures {
		if sig.Header.JSONWebKey != nil {
			_, err = obj.Verify(sig.Header.JSONWebKey)
			if err != nil {
				return fmt.Errorf("error on verify with embedded key %d: %s", i, err)
			}
		}

		// Check that the nonce correctly round-tripped (if present)
		if sig.Header.Nonce != nonce {
			return fmt.Errorf("Incorrect nonce returned: [%s]", sig.Header.Nonce)
		}
	}

	if !bytes.Equal(output, input) {
		return fmt.Errorf("input/output do not match, got '%s', expected '%s'", output, input)
	}

	return nil
}

func TestRoundtripsJWS(t *testing.T) {
	// Test matrix
	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, HS256, HS384, HS512, ES256, ES384, ES512, EdDSA}

	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupter := func(obj *JSONWebSignature) {}

	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)

		for i, serializer := range serializers {
			t.Run(fmt.Sprintf("RoundTripsJWS%d-%s", i, alg), func(t *testing.T) {
				err := RoundtripJWS(alg, serializer, corrupter, signingKey, verificationKey, "test_nonce")
				assert.NoError(t, err)
			})
		}
	}
}

func TestRoundtripsJWSCorruptSignature(t *testing.T) {
	// Test matrix
	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, HS256, HS384, HS512, ES256, ES384, ES512, EdDSA}

	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupters := []func(*JSONWebSignature){
		func(obj *JSONWebSignature) {
			// Changes bytes in signature
			obj.Signatures[0].Signature[10]++
		},
		func(obj *JSONWebSignature) {
			// Set totally invalid signature
			obj.Signatures[0].Signature = []byte("###")
		},
	}

	// Test all different configurations
	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)

		for i, serializer := range serializers {
			for j, corrupter := range corrupters {
				err := RoundtripJWS(alg, serializer, corrupter, signingKey, verificationKey, "test_nonce")
				assert.Error(t, err, "failed to detect corrupt signature alg=%v i=%v j=%v", alg, i, j)
			}
		}
	}
}

// TestSignerWithBrokenRand tests that using a broken random reader with PSS
// signature algorithms returns a valid error.
func TestSignerWithBrokenRand(t *testing.T) {
	// As of go1.20, the random input parameter used in rsa.SignPKCS1v15 is
	// legacy and ignored, and it can be nil meaning that there's no broken
	// random-ness test applicable for signing RS256, RS384, or RS512.
	sigAlgs := []SignatureAlgorithm{PS256, PS384, PS512}

	// We still need to test that users building/testing go-jose on older
	// versions of go will return an error if the random reader is broken.
	if strings.HasPrefix(runtime.Version(), "go1.1") {
		sigAlgs = append(sigAlgs, RS256, RS384, RS512)
	}

	serializer := func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() }
	corrupter := func(obj *JSONWebSignature) {}

	brokenRandReaders := []func() io.Reader{
		// Totally broken
		func() io.Reader { return bytes.NewReader([]byte{}) },
		// Not enough bytes
		func() io.Reader { return io.LimitReader(rand.Reader, 20) },
	}

	defer resetRandReader()

	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)
		for i, getReader := range brokenRandReaders {
			randReader = getReader()
			err := RoundtripJWS(alg, serializer, corrupter, signingKey, verificationKey, "test_nonce")
			assert.Error(t, err, "signer should fail if rand is broken alg=%v i=%v", alg, i)
		}
	}
}

func TestJWSNilVerificationKey(t *testing.T) {
	tests := []struct {
		name            string
		algorithm       SignatureAlgorithm
		verificationKey any
		want            error
	}{
		{name: "Ed25519", algorithm: EdDSA, verificationKey: ed25519.PublicKey(nil), want: errInvalidVerificationKey},
		{name: "ECDSA", algorithm: ES256, verificationKey: (*ecdsa.PublicKey)(nil), want: errInvalidVerificationKey},
		{name: "RSA", algorithm: RS256, verificationKey: (*rsa.PublicKey)(nil), want: errInvalidVerificationKey},
		{name: "JWK", algorithm: RS256, verificationKey: (*JSONWebKey)(nil), want: errInvalidVerificationKey},
		{name: "JWKS", algorithm: RS256, verificationKey: (*JSONWebKeySet)(nil), want: ErrUnsupportedKeyType},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signingKey, _ := GenerateSigningTestKey(test.algorithm)
			signer, err := NewSigner(SigningKey{Algorithm: test.algorithm, Key: signingKey}, nil)
			require.NoError(t, err)
			obj, err := signer.Sign([]byte("payload"))
			require.NoError(t, err)

			_, err = obj.Verify(test.verificationKey)
			require.ErrorIs(t, err, test.want, "Verify() error = %v, want %v", err, test.want)

			_, _, _, err = obj.VerifyMulti(test.verificationKey)
			require.Error(t, err, "VerifyMulti() accepted a nil verification key")
		})
	}
}

func TestJWSInvalidKey(t *testing.T) {
	signingKey0, verificationKey0 := GenerateSigningTestKey(RS256)
	_, verificationKey1 := GenerateSigningTestKey(ES256)
	_, verificationKey2 := GenerateSigningTestKey(EdDSA)

	signer, err := NewSigner(SigningKey{Algorithm: RS256, Key: signingKey0}, nil)
	if err != nil {
		panic(err)
	}

	input := []byte("Lorem ipsum dolor sit amet")
	obj, err := signer.Sign(input)
	if err != nil {
		panic(err)
	}

	// Must work with correct key
	_, err = obj.Verify(verificationKey0)
	assert.NoError(t, err, "error on verify")

	// Must not work with incorrect key
	_, err = obj.Verify(verificationKey1)
	assert.Error(t, err, "verification should fail with incorrect key")

	// Must not work with incorrect key
	_, err = obj.Verify(verificationKey2)
	assert.Error(t, err, "verification should fail with incorrect key")

	// Must not work with invalid key
	_, err = obj.Verify("")
	assert.Error(t, err, "verification should fail with incorrect key")
}

func TestMultiRecipientJWS(t *testing.T) {
	sharedKey := []byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	}
	jwkSharedKey := JSONWebKey{
		KeyID: "123",
		Key:   sharedKey,
	}

	signer, err := NewMultiSigner([]SigningKey{
		{RS256, rsaTestKey},
		{HS384, sharedKey},
		{HS512, jwkSharedKey},
	}, nil)
	require.NoError(t, err, "error creating signer")

	input := []byte("Lorem ipsum dolor sit amet")
	obj, err := signer.Sign(input)
	require.NoError(t, err, "error on sign")

	_, err = obj.CompactSerialize()
	require.Error(t, err, "message with multiple recipient was compact serialized")

	msg := obj.FullSerialize()

	obj, err = ParseSigned(msg, []SignatureAlgorithm{RS256, HS384, HS512})
	require.NoError(t, err, "error on parse")

	i, _, output, err := obj.VerifyMulti(&rsaTestKey.PublicKey)
	require.NoError(t, err, "error on verify")

	require.Equal(t, 0, i, "signature index should be 0 for RSA key")

	require.Equal(t, input, output, "input/output do not match output=%v input=%v", output, input)

	i, _, output, err = obj.VerifyMulti(sharedKey)
	require.NoError(t, err, "error on verify")

	require.Equal(t, 1, i, "signature index should be 1 for EC key")

	require.Equal(t, input, output, "input/output do not match output=%v input=%v", output, input)
}

// TestVerifyMultiJWKSPerSignatureKid checks that VerifyMulti honors different "kid"
// headers on different signatures. It creates a JWS that validates only if the "kid"
// from the second of the two signatures is used.
func TestVerifyMultiJWKSPerSignatureKid(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")

	keyBar, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyFoo, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // only its public key goes in the JWKS
	require.NoError(t, err)

	// Both signatures are produced by keyBar. The "foo" signature is therefore
	// invalid relative to the JWKS, whose "foo" entry is the unrelated keyFoo.
	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "foo", Key: keyBar}},
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "bar", Key: keyBar}},
	}, nil)
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ES256})
	require.NoError(t, err)

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "foo", Key: keyFoo.Public()},
		{KeyID: "bar", Key: keyBar.Public()},
	}}

	idx, sig, out, err := parsed.VerifyMulti(jwks)
	require.NoError(t, err, "VerifyMulti failed")
	assert.Equal(t, 1, idx, "verified signature index = %d, want 1", idx)
	assert.Equal(t, "bar", sig.Header.KeyID, "verified kid = %q, want \"bar\"", sig.Header.KeyID)
	assert.Equal(t, payload, out, "payload mismatch")
}

// TestVerifyMultiJWKSNoMatchingKid checks that VerifyMulti against a JWK Set fails
// with ErrJWKSKidNotFound when there's no key matching the "kid" headers of the
// signatures.
func TestVerifyMultiJWKSNoMatchingKid(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "foo", Key: key}},
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "bar", Key: key}},
	}, nil)
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ES256})
	require.NoError(t, err)

	// The JWKS contains a usable key, but under a kid that matches no signature.
	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "other", Key: key.Public()},
	}}

	_, _, _, err = parsed.VerifyMulti(jwks)
	assert.Error(t, err, "expected error when no signature kid is present in the JWKS")

	// The JWKS contains a usable key matching the second signature.
	jwks = &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "bar", Key: key.Public()},
	}}
	_, _, _, err = parsed.VerifyMulti(jwks)
	assert.NoError(t, err, "verifying with JWK Set that includes 'bar'")
}

// RFC 7515 Section 4.1.3.
func TestSignRefusesToEmbedAPrivateJWK(t *testing.T) {
	testCases := []struct {
		name    string
		initial *JSONWebKey
	}{
		{"PublicAtCreation", &JSONWebKey{Key: &ecTestKey256.PublicKey}},
		{"NoneAtCreation", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sw := makeOpaqueSigner(t, ecTestKey256, ES256)
			sw.pk = tc.initial

			signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: sw}, &SignerOptions{EmbedJWK: true})
			require.NoError(t, err, "NewSigner")

			sw.pk = &JSONWebKey{Key: ecTestKey256}

			_, err = signer.Sign([]byte("payload"))
			require.ErrorIs(t, err, ErrNotPublic, "Sign: got %v, want %v", err, ErrNotPublic)
		})
	}
}

func TestSignChecksExtraHeadersChangedAfterNewSigner(t *testing.T) {
	testCases := []struct {
		name    string
		header  HeaderKey
		value   any
		wantErr error
	}{
		{"PrivateJWK", headerJWK, JSONWebKey{Key: ecTestKey256}, ErrNotPublic},
		{"Algorithm", headerAlgorithm, "none", ErrReservedHeaderParameter},
		{"Base64WithoutCritical", headerB64, false, ErrB64NotCritical},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := (&SignerOptions{}).WithHeader("x", 1)

			signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: ecTestKey256}, opts)
			require.NoError(t, err, "NewSigner")

			opts.ExtraHeaders[tc.header] = tc.value

			_, err = signer.Sign([]byte("payload"))
			assert.ErrorIs(t, err, tc.wantErr, "Sign: got %v, want %v", err, tc.wantErr)
		})
	}
}

func TestSignReturnsAnErrorForAHeaderJSONCannotEncode(t *testing.T) {
	values := map[string]any{
		"NaN":  math.NaN(),
		"Chan": make(chan int),
		"Func": func() {},
	}

	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: bytes.Repeat([]byte{1}, 32)}, (&SignerOptions{}).WithHeader("x", v))
			require.NoError(t, err, "NewSigner")

			_, err = signer.Sign([]byte("payload"))
			assert.Error(t, err, "Sign accepted a header value JSON cannot encode")
		})
	}
}

// RFC 7517 Section 4.3.
func TestEmbeddedJWKVerifiesWhenSigningKeyListsKeyOps(t *testing.T) {
	signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: JSONWebKey{Key: ecTestKey256, KeyOps: []string{"sign"}}}, &SignerOptions{EmbedJWK: true})
	require.NoError(t, err)

	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err)

	serialized, err := obj.CompactSerialize()
	require.NoError(t, err)

	parsed, err := ParseSignedCompact(serialized, []SignatureAlgorithm{ES256})
	require.NoError(t, err)

	embedded := parsed.Signatures[0].Header.JSONWebKey

	assert.Equal(t, []string{"verify"}, embedded.KeyOps)

	_, err = parsed.Verify(embedded)
	assert.NoError(t, err, "Verify with the embedded JWK")
}

// RFC 7515 Section 4.1.11.
func TestNewSignerRejectsInvalidCritical(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)

	testCases := []struct {
		name  string
		opts  func(*SignerOptions)
		valid bool
	}{
		{"NotInHeader", func(so *SignerOptions) { so.WithCritical("nope") }, false},
		{"Empty", func(so *SignerOptions) { so.WithHeader(headerCritical, []string{}) }, false},
		{"Duplicate", func(so *SignerOptions) { so.WithHeader("ext", 1).WithCritical("ext", "ext") }, false},
		{"RegisteredAlgorithm", func(so *SignerOptions) { so.WithCritical(headerAlgorithm) }, false},
		{"RegisteredKeyID", func(so *SignerOptions) { so.WithHeader(headerKeyID, "k").WithCritical(headerKeyID) }, false},
		{"NotAList", func(so *SignerOptions) { so.WithHeader(headerCritical, "ext").WithHeader("ext", 1) }, false},
		{"NotStrings", func(so *SignerOptions) { so.WithHeader(headerCritical, []any{1}) }, false},
		{"Extension", func(so *SignerOptions) { so.WithHeader("ext", 1).WithCritical("ext") }, true},
		{"ExtensionFromJSON", func(so *SignerOptions) { so.WithHeader("ext", 1).WithHeader(headerCritical, []any{"ext"}) }, true},
		{"Base64", func(so *SignerOptions) { so.WithBase64(false) }, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := new(SignerOptions)
			tc.opts(opts)

			signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)
			if !tc.valid {
				assert.ErrorIs(t, err, ErrInvalidCriticalHeader, "NewSigner: got %v, want %v", err, ErrInvalidCriticalHeader)

				return
			}

			require.NoError(t, err, "NewSigner")

			obj, err := signer.Sign([]byte("payload"))
			require.NoError(t, err, "Sign")

			_, err = ParseSignedJSON(obj.FullSerialize(), []SignatureAlgorithm{HS256})
			assert.NoError(t, err, "ParseSignedJSON")
		})
	}
}

func TestWithCriticalAppendsToAnyExistingList(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)

	opts := (&SignerOptions{}).WithHeader(headerCritical, []any{"ext"}).WithHeader("ext", 1).WithCritical("other").WithHeader("other", 2)

	crit := opts.ExtraHeaders[headerCritical]
	assert.Equal(t, []any{"ext", "other"}, crit, "crit = %#v, want both names", crit)

	_, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)
	assert.NoError(t, err, "NewSigner")

	opts = (&SignerOptions{}).WithHeader(headerCritical, "ext").WithHeader("ext", 1).WithCritical("other").WithHeader("other", 2)

	_, err = NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)
	assert.ErrorIs(t, err, ErrInvalidCriticalHeader, "NewSigner: got %v, want %v", err, ErrInvalidCriticalHeader)
}

func TestSignRejectsExtraHeaderTooDeepForTheParser(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	deep := json.RawMessage(strings.Repeat("[", 10000) + strings.Repeat("]", 10000))

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, (&SignerOptions{}).WithHeader("ext", deep))
	if err != nil {
		return
	}

	_, err = signer.Sign([]byte("payload"))
	require.Error(t, err, "Sign accepted a header nested deeper than the parser allows")
}

func TestNewSignerRejectsMismatchedPrivateKey(t *testing.T) {
	_, otherEd, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mismatchedEd := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
	copy(mismatchedEd, ed25519PrivateKey.Seed())
	copy(mismatchedEd[32:], otherEd[32:])

	otherEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mismatchedEC := &ecdsa.PrivateKey{PublicKey: otherEC.PublicKey, D: ecTestKey256.D}

	mismatchedRSA := *rsaTestKey
	mismatchedRSA.PublicKey.N = new(big.Int).Add(rsaTestKey.N, big.NewInt(2))

	testCases := []struct {
		name string
		alg  SignatureAlgorithm
		key  any
	}{
		{"Ed25519", EdDSA, mismatchedEd},
		{"Ed25519WrongLength", EdDSA, ed25519PrivateKey[:32]},
		{"ECDSA", ES256, mismatchedEC},
		{"ECDSAMissingD", ES256, &ecdsa.PrivateKey{PublicKey: ecTestKey256.PublicKey}},
		{"RSA", RS256, &mismatchedRSA},
		{"RSAMissingPrimes", RS256, &rsa.PrivateKey{PublicKey: rsaTestKey.PublicKey, D: rsaTestKey.D}},
		{"Ed25519JWK", EdDSA, &JSONWebKey{Key: mismatchedEd}},
		{"ECDSAJWK", ES256, JSONWebKey{Key: mismatchedEC}},
		{"RSAJWK", RS256, &JSONWebKey{Key: &mismatchedRSA}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewSigner(SigningKey{Algorithm: tc.alg, Key: tc.key}, nil)
			require.Error(t, err, "NewSigner accepted a private key whose public half does not match")
		})
	}
}

func GenerateSigningTestKey(sigAlg SignatureAlgorithm) (sig, ver any) {
	switch sigAlg {
	case EdDSA:
		sig = ed25519PrivateKey
		ver = ed25519PublicKey
	case RS256, RS384, RS512, PS256, PS384, PS512:
		sig = rsaTestKey
		ver = &rsaTestKey.PublicKey
	case HS256, HS384, HS512:
		sig, _, _ = randomKeyGenerator{size: 64}.genKey()
		ver = sig
	case ES256:
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case ES384:
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case ES512:
		key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	default:
		panic("Must update test case")
	}

	return
}

func TestInvalidSignerAlg(t *testing.T) {
	_, err := NewSigner(SigningKey{"XYZ", nil}, nil)
	assert.Error(t, err, "should not accept invalid algorithm")

	_, err = NewSigner(SigningKey{"XYZ", []byte{}}, nil)
	assert.Error(t, err, "should not accept invalid algorithm")
}

func TestInvalidJWS(t *testing.T) {
	signer, err := NewSigner(SigningKey{PS256, rsaTestKey}, nil)
	require.NoError(t, err)

	obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	require.NoError(t, err)
	obj.Signatures[0].header = &rawHeader{}

	// headerB64 is known, but should be in protected
	require.NoError(t, obj.Signatures[0].header.set(headerCritical, []string{headerB64}))

	_, err = obj.Verify(&rsaTestKey.PublicKey)
	assert.Error(t, err, "should not verify message with an unprotected but known crit header")

	// reject unknown critical headers
	obj.Signatures[0].protected = &rawHeader{}
	obj.Signatures[0].header = &rawHeader{}
	require.NoError(t, obj.Signatures[0].protected.set(headerCritical, []string{"unknown-critical-header"}))

	_, err = obj.Verify(&rsaTestKey.PublicKey)
	assert.Error(t, err, "should not verify message with unknown crit header")

	// Try without alg header
	obj.Signatures[0].protected = &rawHeader{}
	obj.Signatures[0].header = &rawHeader{}

	_, err = obj.Verify(&rsaTestKey.PublicKey)
	assert.Error(t, err, "should not verify message with missing headers")
}

func TestSignerKid(t *testing.T) {
	kid := "DEADBEEF"
	payload := []byte("Lorem ipsum dolor sit amet")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err, "problem generating test signing key")

	basejwk := JSONWebKey{Key: key}
	jsonbar, err := basejwk.MarshalJSON()
	assert.NoError(t, err, "problem marshalling base JWK")

	var jsonmsi map[string]any
	err = json.Unmarshal(jsonbar, &jsonmsi)
	assert.NoError(t, err, "problem unmarshalling base JWK")
	jsonmsi["kid"] = kid
	jsonbar2, err := json.Marshal(jsonmsi)
	assert.NoError(t, err, "problem marshalling kided JWK")

	var jwk JSONWebKey
	err = jwk.UnmarshalJSON(jsonbar2)
	assert.NoError(t, err, "problem unmarshalling kided JWK")

	signer, err := NewSigner(SigningKey{ES256, &jwk}, nil)
	assert.NoError(t, err, "problem creating signer with *JSONWebKey")

	signed, err := signer.Sign(payload)
	require.NoError(t, err)

	serialized := signed.FullSerialize()

	parsed, err := ParseSigned(serialized, []SignatureAlgorithm{ES256})
	assert.NoError(t, err, "problem parsing signed object")

	assert.Equal(t, kid, parsed.Signatures[0].Header.KeyID, "KeyID did not survive trip")

	_, err = NewSigner(SigningKey{ES256, jwk}, nil)
	assert.NoError(t, err, "problem creating signer with JSONWebKey")

	// Verify with JWKS
	_, err = parsed.Verify(&JSONWebKeySet{
		Keys: []JSONWebKey{jwk.Public()},
	})
	assert.NoError(t, err, "problem verifying with JWKS")
}

func TestEmbedJwk(t *testing.T) {
	var payload = []byte("Lorem ipsum dolor sit amet")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err, "Failed to generate key")

	signer, err := NewSigner(SigningKey{ES256, key}, &SignerOptions{EmbedJWK: true})
	assert.NoError(t, err, "Failed to create signer")

	object, err := signer.Sign(payload)
	assert.NoError(t, err, "Failed to sign payload")

	object, err = ParseSigned(object.FullSerialize(), []SignatureAlgorithm{ES256})
	assert.NoError(t, err, "Failed to parse jws")

	jwk, err := object.Signatures[0].protected.getJWK()
	if jwk == nil || err != nil {
		assert.Fail(t, "JWK isn't set in protected header")
	}

	// This time, sign and do not embed JWK in message
	signer, err = NewSigner(SigningKey{ES256, key}, &SignerOptions{EmbedJWK: false})
	require.NoError(t, err)

	object, err = signer.Sign(payload)
	assert.NoError(t, err, "Failed to sign payload")

	object, err = ParseSigned(object.FullSerialize(), []SignatureAlgorithm{ES256})
	assert.NoError(t, err, "Failed to parse jws")

	jwk2, err := object.Signatures[0].protected.getJWK()
	assert.NoError(t, err, "JWK is invalid in protected header")
	assert.Nil(t, jwk2, "JWK is set in protected header")
}

func TestSignerOptionsEd(t *testing.T) {
	key, _ := GenerateSigningTestKey(EdDSA)
	opts := &SignerOptions{
		EmbedJWK: true,
	}
	opts.WithContentType("JWT")
	opts.WithType("JWT")
	sig, err := NewSigner(SigningKey{EdDSA, key}, opts)
	assert.NoError(t, err, "Failed to create signer")

	assert.Equal(t, sig.Options(), *opts, "Signer options do not match")
}

func TestSignerOptions(t *testing.T) {
	key, _ := GenerateSigningTestKey(HS256)
	opts := &SignerOptions{
		EmbedJWK: true,
	}
	opts.WithContentType("JWT")
	opts.WithType("JWT")
	sig, err := NewSigner(SigningKey{HS256, key}, opts)
	assert.NoError(t, err, "Failed to create signer")

	assert.Equal(t, sig.Options(), *opts, "Signer options do not match")
}

// Test that extra headers are generated and parsed in a round trip.
func TestSignerExtraHeaderInclusion(t *testing.T) {
	var payload = []byte("Lorem ipsum dolor sit amet")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err, "Failed to generate key")

	signer, err := NewSigner(SigningKey{ES256, key}, (&SignerOptions{}).WithContentType("foo/bar").WithHeader(HeaderKey("myCustomHeader"), "xyz"))
	assert.NoError(t, err, "Failed to create signer")

	object, err := signer.Sign(payload)
	assert.NoError(t, err, "Failed to sign payload")

	object, err = ParseSigned(object.FullSerialize(), []SignatureAlgorithm{ES256})
	assert.NoError(t, err, "Failed to parse jws")

	correct := map[HeaderKey]any{
		HeaderContentType:           "foo/bar",
		HeaderKey("myCustomHeader"): "xyz",
	}

	assert.Equal(t, correct, object.Signatures[0].Header.ExtraHeaders)
}

func TestSignerB64(t *testing.T) {
	// RFC 7797 Appendix, Section 4.2: the payload "$.02" with the HMAC key from
	// RFC 7515 Appendix A.1. Section 5.2 forbids carrying this payload unencoded
	// in a compact serialization, because the '.' would read as a separator, so
	// the specification gives only the detached form.
	const detached = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..A5dxf2s96_n5FLueVuW1Z_vh161FwXZC4YLPff6dmDY"

	key := []byte{
		0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc, 0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
		0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28, 0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
		0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef, 0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
		0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08, 0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
	}

	opts := new(SignerOptions)
	opts.WithBase64(false)

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)
	require.NoError(t, err, "Failed to create signer")

	input := []byte("$.02")

	obj, err := signer.Sign(input)
	require.NoError(t, err, "Failed to sign payload")

	// The detached serialization must match the specification byte for byte.
	msg, err := obj.DetachedCompactSerialize()
	require.NoError(t, err, "Failed to serialize detached")

	assert.Equal(t, msg, detached, "Invalid detached serialization, got '%s', expected '%s'", msg, detached)

	parsed, err := ParseDetached(msg, input, []SignatureAlgorithm{HS256})
	require.NoError(t, err, "Error on parse")

	err = parsed.DetachedVerify(input, key)
	assert.NoError(t, err, "Error on verify")

	// Non-detached is refused for this payload, per RFC 7797 Section 5.2.
	_, err = obj.CompactSerialize()
	assert.ErrorIs(t, err, ErrNotSupported, "CompactSerialize of an unencoded payload containing '.' returned %v, want %v", err, ErrNotSupported)
}

// RFC 7797 Section 5.2 permits an unencoded non-detached payload when it carries
// no '.'. The payload used to be base64url encoded on the wire anyway, in both
// serializations, so the library emitted a token that declared "b64":false while
// carrying an encoded payload, and could not read a conforming one.
func TestSignerB64NonDetached(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")
	input := []byte("NDA1")

	opts := new(SignerOptions)
	opts.WithBase64(false)

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)
	require.NoError(t, err, "NewSigner")

	obj, err := signer.Sign(input)
	require.NoError(t, err, "Sign")

	compact, err := obj.CompactSerialize()
	require.NoError(t, err, "CompactSerialize")

	// The payload segment has to be the payload itself, not its encoding.
	segments := strings.Split(compact, ".")
	assert.Equal(t, string(input), segments[1])

	// And the JSON serialization carries it literally too, per Section 5.3.
	var members map[string]any
	err = json.Unmarshal([]byte(obj.FullSerialize()), &members)
	require.NoError(t, err, "unmarshal")

	assert.Equal(t, string(input), members["payload"])

	// Both serializations must round-trip.
	for name, serialized := range map[string]string{"compact": compact, "json": obj.FullSerialize()} {
		parsed, err := ParseSigned(serialized, []SignatureAlgorithm{HS256})
		if !assert.NoError(t, err, "%s: ParseSigned", name) {
			continue
		}

		output, err := parsed.Verify(key)
		if !assert.NoError(t, err, "%s: Verify", name) {
			continue
		}

		assert.Equal(t, input, output, "%s: payload = %q, want %q", name, output, input)
	}
}

func TestSignerB64NonDetachedRejectsWhitespaceInCompact(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	opts := new(SignerOptions)
	opts.WithBase64(false)

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)
	require.NoError(t, err, "NewSigner")

	for _, input := range []string{"a b", "a\tb", "a\nb", "a b"} {
		t.Run(fmt.Sprintf("%q", input), func(t *testing.T) {
			obj, err := signer.Sign([]byte(input))
			require.NoError(t, err, "Sign")

			_, err = obj.CompactSerialize()
			require.ErrorIs(t, err, ErrNotSupported, "CompactSerialize error = %v, want ErrNotSupported", err)

			// The payload can still be detached, or carried by the JSON serialization.
			detached, err := obj.DetachedCompactSerialize()
			require.NoError(t, err, "DetachedCompactSerialize")

			parsed, err := ParseDetached(detached, []byte(input), []SignatureAlgorithm{HS256})
			require.NoError(t, err, "ParseDetached")

			_, err = parsed.Verify(key)
			require.NoError(t, err, "Verify detached")

			parsed, err = ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{HS256})
			require.NoError(t, err, "ParseSigned JSON")

			output, err := parsed.Verify(key)
			require.NoError(t, err, "Verify JSON")

			assert.Equal(t, input, string(output), "payload = %q, want %q", output, input)
		})
	}
}

func BenchmarkParseSigned(b *testing.B) {
	msg := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c`
	for i := 0; i < b.N; i++ {
		_, err := ParseSigned(msg, []SignatureAlgorithm{HS256})
		if err != nil {
			b.Errorf("Error on parse: %s", err)
		}
	}
}

func TestVerifyJWKSDuplicateKid(t *testing.T) {
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	payload := []byte("Lorem ipsum dolor sit amet")

	signer, err := NewSigner(SigningKey{
		Algorithm: ES256,
		Key:       &JSONWebKey{KeyID: "shared", Key: signing},
	}, nil)
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)

	correct := JSONWebKey{KeyID: "shared", Key: signing.Public()}
	decoy := JSONWebKey{KeyID: "shared", Key: other.Public()}

	for _, tc := range []struct {
		name string
		keys []JSONWebKey
	}{
		{"CorrectKeyFirst", []JSONWebKey{correct, decoy}},
		{"CorrectKeyLast", []JSONWebKey{decoy, correct}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ES256})
			require.NoError(t, err)

			out, err := parsed.Verify(&JSONWebKeySet{Keys: tc.keys})
			require.NoError(t, err, "Verify failed")
			assert.Equal(t, payload, out, "payload mismatch")
		})
	}
}

func TestVerifyJWKSUnusableKeyReportsKeyError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := NewSigner(SigningKey{
		Algorithm: ES256,
		Key:       &JSONWebKey{KeyID: "shared", Key: key},
	}, nil)
	require.NoError(t, err)
	obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	require.NoError(t, err)

	parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ES256})
	require.NoError(t, err)

	_, err = parsed.Verify(&JSONWebKeySet{Keys: []JSONWebKey{{KeyID: "shared", Key: "not a key"}}})

	assert.ErrorIs(t, err, ErrUnsupportedKeyType, "expected ErrUnsupportedKeyType, got: %v", err)
}

// The protected header used to be seeded with the real algorithm and then have ExtraHeaders copied over the top,
// so WithHeader("alg", ...) won the collision and the library signed with one algorithm under a header claiming
// another. The signature covers the bogus header, so the token is internally consistent and simply unverifiable.
// The same mechanism desynchronised "b64" from the "crit" entry RFC 7797 Section 6 requires alongside it, which
// produces a JWS this package now refuses to parse.
func TestNewSignerRejectsUnusableExtraHeaders(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	testCases := []struct {
		name    string
		opts    func(*SignerOptions)
		wantErr error
	}{
		{
			"AlgorithmOverride",
			func(so *SignerOptions) { so.WithHeader(headerAlgorithm, "TOTALLY-BOGUS") },
			ErrReservedHeaderParameter,
		},
		{
			"AlgorithmOverrideMatchingTheKey",
			func(so *SignerOptions) { so.WithHeader(headerAlgorithm, string(HS256)) },
			ErrReservedHeaderParameter,
		},
		{
			"Base64WithoutCritical",
			func(so *SignerOptions) { so.WithHeader(headerB64, false) },
			ErrB64NotCritical,
		},
		{
			"Base64ThroughTheSupportedRoute",
			func(so *SignerOptions) { so.WithBase64(false) },
			nil,
		},
		{
			// A caller which round-trips its headers through JSON gets the list back as []any.
			"Base64WithCriticalFromJSON",
			func(so *SignerOptions) {
				so.WithHeader(headerB64, false).WithHeader(headerCritical, []any{"b64"})
			},
			nil,
		},
		{
			// RFC 7515 Section 4.1.3.
			"PrivateJWK",
			func(so *SignerOptions) { so.WithHeader(headerJWK, JSONWebKey{Key: ecTestKey256}) },
			ErrNotPublic,
		},
		{
			"PrivateJWKAsJSON",
			func(so *SignerOptions) {
				raw, _ := JSONWebKey{Key: ecTestKey256}.MarshalJSON()

				var m map[string]any

				_ = json.Unmarshal(raw, &m)

				so.WithHeader(headerJWK, m)
			},
			ErrNotPublic,
		},
		{
			"PublicJWK",
			func(so *SignerOptions) { so.WithHeader(headerJWK, JSONWebKey{Key: &ecTestKey256.PublicKey}) },
			nil,
		},
		{
			"JWKWithEmbedJWK",
			func(so *SignerOptions) {
				so.EmbedJWK = true
				so.WithHeader(headerJWK, JSONWebKey{Key: &ecTestKey256.PublicKey})
			},
			ErrReservedHeaderParameter,
		},
		{
			"KeyIDIsTheCallersToSet",
			func(so *SignerOptions) { so.WithHeader(headerKeyID, "mine") },
			nil,
		},
		{
			"NoExtraHeaders",
			func(so *SignerOptions) {},
			nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := new(SignerOptions)
			tc.opts(opts)

			signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, "NewSigner: got %v, want %v", err, tc.wantErr)

				return
			}

			require.NoError(t, err, "NewSigner")

			// What the signer does accept has to still round-trip, header and payload both.
			obj, err := signer.Sign([]byte("NDA1"))
			require.NoError(t, err, "Sign")

			serialized, err := obj.CompactSerialize()
			require.NoError(t, err, "CompactSerialize")

			parsed, err := ParseSignedCompact(serialized, []SignatureAlgorithm{HS256})
			require.NoError(t, err, "ParseSignedCompact")

			_, err = parsed.Verify(key)
			require.NoError(t, err, "Verify")

			alg := parsed.Signatures[0].Protected.Algorithm
			assert.Equal(t, string(HS256), alg, "protected alg = %q, want %q", alg, HS256)
		})
	}
}

func TestDetachedVerifyWithoutSignatures(t *testing.T) {
	obj := &JSONWebSignature{}

	err := obj.DetachedVerify([]byte("payload"), []byte("0123456789ABCDEF0123456789ABCDEF"))
	assert.Error(t, err, "DetachedVerify on an object with no signatures returned no error")
}

func TestSignPopulatesTheSignatureFields(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	opts := (&SignerOptions{}).WithType("JWT").WithHeader(headerKeyID, "k1")

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, opts)
	require.NoError(t, err, "NewSigner")

	obj, err := signer.Sign([]byte("NDA1"))
	require.NoError(t, err, "Sign")

	require.Len(t, obj.Signatures, 1)

	signed := obj.Signatures[0]

	for name, header := range map[string]Header{"Header": signed.Header, "Protected": signed.Protected} {
		assert.Equal(t, string(HS256), header.Algorithm, "%s.Algorithm = %q, want %q", name, header.Algorithm, HS256)

		assert.Equal(t, "k1", header.KeyID, "%s.KeyID = %q, want %q", name, header.KeyID, "k1")

		if typ := header.ExtraHeaders[HeaderType]; typ == nil {
			assert.Failf(t, "unexpected result", "%s carries no typ", name)
		}
	}

	serialized, err := obj.CompactSerialize()
	require.NoError(t, err, "CompactSerialize")

	parsed, err := ParseSignedCompact(serialized, []SignatureAlgorithm{HS256})
	require.NoError(t, err, "ParseSignedCompact")

	assert.Equal(t, signed.Header.Algorithm, parsed.Signatures[0].Header.Algorithm)

	assert.Equal(t, signed.Header.KeyID, parsed.Signatures[0].Header.KeyID)

	assert.Equal(t, signed.Header.ExtraHeaders, parsed.Signatures[0].Header.ExtraHeaders)

	signed.Header.ExtraHeaders[HeaderKey("scratch")] = true

	_, ok := signed.Protected.ExtraHeaders[HeaderKey("scratch")]
	assert.False(t, ok, "Header and Protected share their ExtraHeaders map")
}

func TestSignUnmarshalableExtraHeader(t *testing.T) {
	signer, err := NewSigner(SigningKey{Algorithm: RS256, Key: rsaTestKey}, (&SignerOptions{}).WithHeader("x", make(chan int)))
	require.NoError(t, err)
	_, err = signer.Sign([]byte("payload"))
	assert.Error(t, err, "expected error signing with unmarshalable extra header")
}

func TestNewMultiSignerRespectsMaxSignatures(t *testing.T) {
	defer func(old int) { MaxSignatures = old }(MaxSignatures)

	MaxSignatures = 1

	key := make([]byte, 32)
	sigs := []SigningKey{{Algorithm: HS256, Key: key}, {Algorithm: HS256, Key: key}}

	_, err := NewMultiSigner(sigs, nil)
	assert.ErrorContains(t, err, "too many signatures", "expected too many signatures error")

	MaxSignatures = 2

	_, err = NewMultiSigner(sigs, nil)
	assert.NoError(t, err, "unexpected error")
}

func TestNewSignerRejectsNilJSONWebKey(t *testing.T) {
	var key *JSONWebKey

	_, err := NewSigner(SigningKey{Algorithm: ES256, Key: key}, nil)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)

	_, err = NewMultiSigner([]SigningKey{{Algorithm: ES256, Key: key}}, nil)
	assert.ErrorIs(t, err, ErrUnsupportedKeyType)
}
