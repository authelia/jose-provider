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

package jose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
)

type signWrapper struct {
	pk      *JSONWebKey
	wrapped payloadSigner
	algs    []SignatureAlgorithm
}

var _ = OpaqueSigner(&signWrapper{})

func (sw *signWrapper) Algs() []SignatureAlgorithm {
	return sw.algs
}

func (sw *signWrapper) Public() *JSONWebKey {
	return sw.pk
}

func (sw *signWrapper) SignPayload(payload []byte, alg SignatureAlgorithm) ([]byte, error) {
	sig, err := sw.wrapped.signPayload(payload, alg)
	if err != nil {
		return nil, err
	}
	return sig.Signature, nil
}

type verifyWrapper struct {
	wrapped []payloadVerifier
}

var _ = OpaqueVerifier(&verifyWrapper{})

func (vw *verifyWrapper) VerifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	if len(vw.wrapped) == 0 {
		return fmt.Errorf("error: verifier had no keys")
	}
	var err error
	for _, v := range vw.wrapped {
		err = v.verifyPayload(payload, signature, alg)
		if err == nil {
			return nil
		}
	}
	return err
}

type keyEncryptWrapper struct {
	kid     string
	wrapped keyEncrypter
	algs    []KeyAlgorithm
}

var _ = OpaqueKeyEncrypter(&keyEncryptWrapper{})

func (kew *keyEncryptWrapper) KeyID() string {
	return kew.kid
}

func (kew *keyEncryptWrapper) Algs() []KeyAlgorithm {
	return kew.algs
}

func (kew *keyEncryptWrapper) encryptKey(cek []byte, alg KeyAlgorithm) (recipientInfo, error) {
	info, err := kew.wrapped.encryptKey(cek, alg)
	if err != nil {
		return recipientInfo{}, err
	}

	return info, nil
}

type keyDecryptWrapper struct {
	wrapped keyDecrypter
}

var _ = OpaqueKeyDecrypter(&keyDecryptWrapper{})

func (kdw *keyDecryptWrapper) DecryptKey(encryptedKey []byte, header Header) ([]byte, error) {
	rawHeader := rawHeader{}

	err := rawHeader.set(headerKeyID, header.KeyID)
	if err != nil {
		return nil, err
	}
	err = rawHeader.set(headerAlgorithm, header.Algorithm)
	if err != nil {
		return nil, err
	}
	err = rawHeader.set(headerNonce, header.Nonce)
	if err != nil {
		return nil, err
	}
	err = rawHeader.set(headerJWK, header.JSONWebKey)
	if err != nil {
		return nil, err
	}
	for k, v := range header.ExtraHeaders {
		err = rawHeader.set(k, v)
		if err != nil {
			return nil, err
		}
	}

	recipient := &recipientInfo{
		encryptedKey: encryptedKey,
	}

	var generator randomKeyGenerator
	cipher := getContentCipher(rawHeader.getEncryption())
	if cipher != nil {
		generator = randomKeyGenerator{
			size: cipher.keySize(),
		}
	}

	return kdw.wrapped.decryptKey(rawHeader, recipient, generator)
}

func TestRoundtripsJWSOpaque(t *testing.T) {
	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	corrupter := func(obj *JSONWebSignature) {}

	for _, alg := range sigAlgs {
		signingKey, verificationKey := GenerateSigningTestKey(alg)

		for i, serializer := range serializers {
			sw := makeOpaqueSigner(t, signingKey, alg)
			vw := makeOpaqueVerifier(t, []any{verificationKey}, alg)

			err := RoundtripJWS(alg, serializer, corrupter, sw, verificationKey, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}

			err = RoundtripJWS(alg, serializer, corrupter, signingKey, vw, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}

			err = RoundtripJWS(alg, serializer, corrupter, sw, vw, "test_nonce")
			if err != nil {
				t.Error(err, alg, i)
			}
		}
	}
}

func TestOpaqueSignerRefusesAPublicKeyTheVerifierRejects(t *testing.T) {
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	var lowOrder ed25519.PublicKey
	for k := range weakEd25519PublicKeys {
		lowOrder = ed25519.PublicKey(k[:])
		break
	}

	testCases := []struct {
		name string
		alg  SignatureAlgorithm
		key  any
		err  error
	}{
		{"RSATooSmall", RS256, &smallRSA.PublicKey, ErrInvalidKeySize},
		{"RSAEvenExponent", PS256, &rsa.PublicKey{N: rsaTestKey.N, E: 65536}, errInvalidRSAExponent},
		{"ECDSACurveForAnotherAlgorithm", ES256, &ecTestKey384.PublicKey, nil},
		{"Ed25519LowOrder", EdDSA, lowOrder, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sw := &signWrapper{pk: &JSONWebKey{Key: tc.key}, algs: []SignatureAlgorithm{tc.alg}}

			_, err := NewSigner(SigningKey{Algorithm: tc.alg, Key: sw}, nil)
			if err == nil {
				t.Fatal("NewSigner accepted a public key the verifier rejects")
			}

			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Errorf("NewSigner: got %v, want %v", err, tc.err)
			}
		})
	}
}

func TestOpaqueSignerRefusesARotatedPublicKeyTheVerifierRejects(t *testing.T) {
	sw := makeOpaqueSigner(t, rsaTestKey, RS256)

	signer, err := NewSigner(SigningKey{Algorithm: RS256, Key: sw}, nil)
	if err != nil {
		t.Fatal(err)
	}

	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	sw.pk = &JSONWebKey{Key: &smallRSA.PublicKey}

	if _, err = signer.Sign([]byte("payload")); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("Sign: got %v, want %v", err, ErrInvalidKeySize)
	}
}

func makeOpaqueSigner(t *testing.T, signingKey any, alg SignatureAlgorithm) *signWrapper {
	ri, err := makeJWSRecipient(alg, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	return &signWrapper{
		wrapped: ri.signer,
		algs:    []SignatureAlgorithm{alg},
		pk:      ri.publicKey(),
	}
}

func makeOpaqueVerifier(t *testing.T, verificationKey []any, alg SignatureAlgorithm) *verifyWrapper {
	verifiers := []payloadVerifier{}
	for _, vk := range verificationKey {
		verifier, err := newVerifier(vk)
		if err != nil {
			t.Fatal(err)
		}
		verifiers = append(verifiers, verifier)
	}
	return &verifyWrapper{wrapped: verifiers}
}

func TestRoundtripsJWEOpaque(t *testing.T) {
	keyAlgs := []KeyAlgorithm{RSA1_5, RSA_OAEP, RSA_OAEP_256}
	encs := []ContentEncryption{A128GCM, A256GCM, A128CBC_HS256, A256CBC_HS512}

	serializers := []func(*JSONWebEncryption) (string, error){
		func(obj *JSONWebEncryption) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebEncryption) (string, error) { return obj.FullSerialize(), nil },
	}

	for _, alg := range keyAlgs {
		for _, enc := range encs {
			for i, serializer := range serializers {
				ke := makeOpaqueKeyEncrypter(t, &rsaTestKey.PublicKey, alg, "test-kid")
				kd := makeOpaqueKeyDecrypter(t, rsaTestKey, alg)

				encrypter, err := NewEncrypter(enc, Recipient{Algorithm: alg, Key: ke}, nil)
				if err != nil {
					t.Fatal(err, alg, enc, i)
				}

				plaintext := []byte("foo bar baz")
				jwe, err := encrypter.Encrypt(plaintext)
				if err != nil {
					t.Fatal(err, alg, enc, i)
				}

				jwe = jweSerialize(t, serializer, jwe, kd, alg, enc)

				decrypted, err := jwe.Decrypt(kd)
				if err != nil {
					t.Fatal(err, alg, enc, i)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Errorf("alg %s enc %s serializer %d: got %q, want %q", alg, enc, i, decrypted, plaintext)
				}
			}
		}
	}
}

func makeOpaqueKeyEncrypter(t *testing.T, signingKey any, alg KeyAlgorithm, kid string) *keyEncryptWrapper {
	rki, err := makeJWERecipient(alg, signingKey)
	if err != nil {
		t.Fatal(err, alg)
	}
	return &keyEncryptWrapper{
		wrapped: rki.keyEncrypter,
		algs:    []KeyAlgorithm{alg},
		kid:     kid,
	}
}

func makeOpaqueKeyDecrypter(t *testing.T, decryptionKey any, alg KeyAlgorithm) *keyDecryptWrapper {
	kd, err := newDecrypter(decryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	return &keyDecryptWrapper{
		wrapped: kd,
	}
}

func TestOpaqueSignerKeyRotation(t *testing.T) {

	sigAlgs := []SignatureAlgorithm{RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA}

	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}

	for _, alg := range sigAlgs {
		for i, serializer := range serializers {
			sk1, pk1 := GenerateSigningTestKey(alg)
			sk2, pk2 := GenerateSigningTestKey(alg)

			sw := makeOpaqueSigner(t, sk1, alg)
			sw.pk.KeyID = "first"
			vw := makeOpaqueVerifier(t, []any{pk1, pk2}, alg)

			signer, err := NewSigner(
				SigningKey{Algorithm: alg, Key: sw},
				&SignerOptions{NonceSource: staticNonceSource("test_nonce")},
			)
			if err != nil {
				t.Fatal(err, alg, i)
			}

			jws1, err := signer.Sign([]byte("foo bar baz"))
			if err != nil {
				t.Fatal(err, alg, i)
			}
			jws1 = rtSerialize(t, serializer, jws1, vw, alg)
			if kid := jws1.Signatures[0].Protected.KeyID; kid != "first" {
				t.Errorf("expected kid %q but got %q", "first", kid)
			}

			swNext := makeOpaqueSigner(t, sk2, alg)
			swNext.pk.KeyID = "next"
			sw.wrapped = swNext.wrapped
			sw.pk = swNext.pk

			jws2, err := signer.Sign([]byte("foo bar baz next"))
			if err != nil {
				t.Error(err, alg, i)
			}
			jws2 = rtSerialize(t, serializer, jws2, vw, alg)
			if kid := jws2.Signatures[0].Protected.KeyID; kid != "next" {
				t.Errorf("expected kid %q but got %q", "next", kid)
			}
		}
	}
}

func rtSerialize(t *testing.T, serializer func(*JSONWebSignature) (string, error), sig *JSONWebSignature, vk any, alg SignatureAlgorithm) *JSONWebSignature {
	b, err := serializer(sig)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = ParseSigned(b, []SignatureAlgorithm{alg})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sig.Verify(vk); err != nil {
		t.Fatal(err)
	}
	return sig
}

func jweSerialize(t *testing.T,
	serializer func(*JSONWebEncryption) (string, error),
	jwe *JSONWebEncryption,
	d OpaqueKeyDecrypter,
	alg KeyAlgorithm,
	enc ContentEncryption,
) *JSONWebEncryption {
	b, err := serializer(jwe)
	if err != nil {
		t.Fatal(err)
	}
	jwe, err = ParseEncrypted(b, []KeyAlgorithm{alg}, []ContentEncryption{enc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwe.Decrypt(d); err != nil {
		t.Fatal(err)
	}
	return jwe
}

type badSigner struct {
	*ecdsa.PrivateKey
}

func (bs badSigner) Algs() []SignatureAlgorithm {
	return []SignatureAlgorithm{ES256}
}

func (bs badSigner) SignPayload([]byte, SignatureAlgorithm) ([]byte, error) {
	panic("Shouldn't be called in this test")
}

func (bs badSigner) Public() *JSONWebKey {
	return &JSONWebKey{
		Key:   bs.PrivateKey,
		KeyID: "BS",
	}
}

// TestOpaqueSignerNonPublic ensures a private key returned in Public() doesn't end up in an embedded JWK
func TestOpaqueSignerNonPublic(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var os OpaqueSigner = badSigner{key}
	_, err := NewSigner(SigningKey{Algorithm: ES256, Key: os}, &SignerOptions{EmbedJWK: true})
	if !errors.Is(err, ErrNotPublic) {
		t.Fatal("Expected ErrNotPublic when using BadSigner")
	}
}
