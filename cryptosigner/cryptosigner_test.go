/*-
 * Copyright 2018 Square Inc.
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

package cryptosigner

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"testing"

	"authelia.com/provider/jose"
)

func TestRoundtripsJWSCryptoSigner(t *testing.T) {
	sigAlgs := []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.Ed25519}

	serializers := []func(*jose.JSONWebSignature) (string, error){
		func(obj *jose.JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *jose.JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	for _, alg := range sigAlgs {
		signingKey, verificationKey := generateSigningTestKey(alg)

		for i, serializer := range serializers {
			err := roundtripJWS(alg, serializer, Opaque(signingKey.(crypto.Signer)), verificationKey)
			if err != nil {
				t.Error(err, alg, i)
			}
		}
	}
}

func TestSignPayloadRejectsMalformedECDSASignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der := func(r, s *big.Int) []byte {
		b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			t.Fatal(err)
		}

		return b
	}

	one := big.NewInt(1)
	order := elliptic.P256().Params().N

	extraInteger, err := asn1.Marshal(struct{ R, S, T *big.Int }{one, one, one})
	if err != nil {
		t.Fatal(err)
	}

	testCases := map[string][]byte{
		"RIsOrder":      der(order, one),
		"SIsOrder":      der(one, order),
		"ExtraInteger":  extraInteger,
		"RTooLong":      der(new(big.Int).Lsh(one, 256), one),
		"STooLong":      der(one, new(big.Int).Lsh(one, 256)),
		"RNegative":     der(big.NewInt(-1), one),
		"SZero":         der(one, big.NewInt(0)),
		"TrailingBytes": append(der(one, one), 0),
		"NotDER":        {0x01},
	}

	for name, sig := range testCases {
		t.Run(name, func(t *testing.T) {
			signer := Opaque(derSigner{key: key, sig: sig})

			if _, err := signer.SignPayload([]byte("payload"), jose.ES256); err == nil {
				t.Error("SignPayload accepted a malformed signature")
			}
		})
	}
}

type staticNonceSource string

func (sns staticNonceSource) Nonce() (string, error) {
	return string(sns), nil
}

func roundtripJWS(sigAlg jose.SignatureAlgorithm, serializer func(*jose.JSONWebSignature) (string, error), signingKey any, verificationKey any) error {
	nonce := "test_nonce"
	opts := &jose.SignerOptions{
		NonceSource: staticNonceSource(nonce),
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: sigAlg, Key: signingKey}, opts)
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

	obj, err = jose.ParseSigned(msg, []jose.SignatureAlgorithm{sigAlg})
	if err != nil {
		return fmt.Errorf("error on parse: %s", err)
	}

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

func generateSigningTestKey(sigAlg jose.SignatureAlgorithm) (sig, ver any) {
	switch sigAlg {
	case jose.EdDSA, jose.Ed25519:
		ver, sig, _ = ed25519.GenerateKey(rand.Reader)
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		rsaTestKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		sig = rsaTestKey
		ver = &rsaTestKey.PublicKey
	case jose.ES256:
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case jose.ES384:
		key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	case jose.ES512:
		key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		sig = key
		ver = &key.PublicKey
	default:
		panic("Must update test case")
	}
	return
}

type fakeSigner struct{}

func (fakeSigner) Public() crypto.PublicKey {
	return []byte("fake-key")
}

func (fakeSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not a signer")
}

func TestSignPayloadRejectsTypedNilECDSAKey(t *testing.T) {
	if _, err := Opaque(nilECDSASigner{}).SignPayload([]byte("payload"), jose.ES256); !errors.Is(err, jose.ErrUnsupportedAlgorithm) {
		t.Fatalf("SignPayload() error = %v; want %v", err, jose.ErrUnsupportedAlgorithm)
	}
}

func Test_cryptoSigner_Algs(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		signer crypto.Signer
	}

	tests := []struct {
		name   string
		fields fields
		want   []jose.SignatureAlgorithm
	}{
		{"EdDSA", fields{edKey}, []jose.SignatureAlgorithm{jose.Ed25519, jose.EdDSA}},
		{"ES256", fields{p256}, []jose.SignatureAlgorithm{jose.ES256}},
		{"ES384", fields{p384}, []jose.SignatureAlgorithm{jose.ES384}},
		{"ES512", fields{p521}, []jose.SignatureAlgorithm{jose.ES512}},
		{"RSA", fields{rsaKey}, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512}},
		{"fail P-224", fields{p224}, nil},
		{"fail other", fields{fakeSigner{}}, nil},
		{"fail typed-nil ecdsa", fields{nilECDSASigner{}}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := &cryptoSigner{
				signer: tt.fields.signer,
			}
			if got := cs.Algs(); !reflect.DeepEqual(tt.want, got) {
				t.Errorf("cryptoSigner.Algs() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// RFC 7518 Section 3.5 requires the PSS salt to be the same size as the hash output. The signer previously asked for
// the automatic length, which crypto/rsa treats as the largest the key allows when signing, so verifiers which hold
// to the RFC rejected the signature.
func TestSignPayloadUsesPSSSaltLengthEqualToHash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		alg  jose.SignatureAlgorithm
		hash crypto.Hash
	}{
		{jose.PS256, crypto.SHA256},
		{jose.PS384, crypto.SHA384},
		{jose.PS512, crypto.SHA512},
	}

	payload := []byte("payload")

	for _, tc := range testCases {
		t.Run(string(tc.alg), func(t *testing.T) {
			signature, err := Opaque(key).SignPayload(payload, tc.alg)
			if err != nil {
				t.Fatal(err)
			}

			hasher := tc.hash.New()
			hasher.Write(payload)

			opts := &rsa.PSSOptions{SaltLength: tc.hash.Size(), Hash: tc.hash}

			if err = rsa.VerifyPSS(&key.PublicKey, tc.hash, hasher.Sum(nil), signature, opts); err != nil {
				t.Fatalf("signature does not use a salt the size of the hash: %v", err)
			}
		})
	}
}

func TestSignPayloadRejectsAlgorithmTheKeyDoesNotSupport(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name string
		key  crypto.Signer
		alg  jose.SignatureAlgorithm
	}{
		{"ShouldRejectES256WithP384", p384, jose.ES256},
		{"ShouldRejectES512WithP256", p256, jose.ES512},
		{"ShouldRejectES256WithRSA", rsaKey, jose.ES256},
		{"ShouldRejectRS256WithECDSA", p256, jose.RS256},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Opaque(tc.key).SignPayload([]byte("payload"), tc.alg); !errors.Is(err, jose.ErrUnsupportedAlgorithm) {
				t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
			}
		})
	}
}

type nilECDSASigner struct{}

func (nilECDSASigner) Public() crypto.PublicKey {
	return (*ecdsa.PublicKey)(nil)
}

func (nilECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("nilECDSASigner: Sign unexpectedly called")
}

type derSigner struct {
	key *ecdsa.PrivateKey
	sig []byte
}

func (s derSigner) Public() crypto.PublicKey {
	return &s.key.PublicKey
}

func (s derSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.sig, nil
}
