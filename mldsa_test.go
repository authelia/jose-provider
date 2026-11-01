//go:build go1.27

/*-
 * Copyright 2026 The Go JOSE Authors.
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
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose/json"
)

func TestMLDSAAlgParamsRoundtrip(t *testing.T) {
	for _, alg := range mldsaAlgs {
		params, ok := mldsaParamsFor(alg)
		require.True(t, ok, "mldsaParamsFor(%s) = _, false; want true", alg)
		got, ok := mldsaAlgFor(params)
		if !ok || got != alg {
			assert.Failf(t, "unexpected result", "mldsaAlgFor(%v) = %q, %v; want %q, true", params, got, ok, alg)
		}
	}
}

func TestMLDSAAlgParamsRejectsUnknown(t *testing.T) {
	_, ok := mldsaParamsFor(EdDSA)
	assert.False(t, ok, "mldsaParamsFor(EdDSA) = _, true; want false")
	_, ok = mldsaParamsFor(SignatureAlgorithm("ML-DSA-99"))
	assert.False(t, ok, "mldsaParamsFor(\"ML-DSA-99\") = _, true; want false")
	_, ok = mldsaAlgFor(mldsa.Parameters{})
	assert.False(t, ok, "mldsaAlgFor(zero Parameters) = _, true; want false")
}

func TestMLDSAKeyPredicates(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		privJWK := &JSONWebKey{Key: priv}
		pubJWK := &JSONWebKey{Key: priv.PublicKey()}

		assert.False(t, privJWK.IsPublic(), "%s: private key JWK reported as public", alg)
		assert.True(t, pubJWK.IsPublic(), "%s: public key JWK not reported as public", alg)
		assert.True(t, privJWK.Valid(), "%s: private key JWK reported invalid", alg)
		assert.True(t, pubJWK.Valid(), "%s: public key JWK reported invalid", alg)

		derived := privJWK.Public()
		require.True(t, derived.IsPublic(), "%s: Public() did not return a public key", alg)
		got, ok := derived.Key.(*mldsa.PublicKey)
		require.True(t, ok, "%s: Public() returned %T; want *mldsa.PublicKey", alg, derived.Key)
		assert.True(t, got.Equal(priv.PublicKey()), "%s: Public() returned the wrong public key", alg)

		// Public() on an already-public key is the identity.
		again := pubJWK.Public()
		assert.True(t, again.IsPublic(), "%s: Public() on a public key did not round-trip", alg)
	}
}

func TestMLDSANilKeysAreInvalid(t *testing.T) {
	var (
		nilPriv *mldsa.PrivateKey
		nilPub  *mldsa.PublicKey
	)
	assert.False(t, (&JSONWebKey{Key: nilPriv}).Valid(), "nil *mldsa.PrivateKey reported valid")
	assert.False(t, (&JSONWebKey{Key: nilPub}).Valid(), "nil *mldsa.PublicKey reported valid")
}

func TestMLDSAUnusableKeysDoNotPanic(t *testing.T) {
	var nilPriv *mldsa.PrivateKey
	var nilPub *mldsa.PublicKey
	zeroPriv := new(mldsa.PrivateKey)
	zeroPub := new(mldsa.PublicKey)

	t.Run("private", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  *mldsa.PrivateKey
		}{
			{"typed-nil", nilPriv},
			{"zero-value", zeroPriv},
		} {
			t.Run(tc.name, func(t *testing.T) {
				jwk := &JSONWebKey{Key: tc.key}

				assert.False(t, jwk.Valid(), "Valid() = true; want false")
				assert.False(t, jwk.IsPublic(), "IsPublic() = true; want false")
				_, err := NewSigner(SigningKey{Algorithm: ML_DSA_65, Key: tc.key}, nil)
				assert.Error(t, err, "NewSigner accepted the key")
				_, err = jwk.MarshalJSON()
				assert.Error(t, err, "MarshalJSON accepted the key")
				_, err = jwk.Thumbprint(crypto.SHA256)
				assert.Error(t, err, "Thumbprint accepted the key")
			})
		}
	})

	realPriv := mldsaTestKey(t, ML_DSA_65)
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_65, Key: realPriv}, nil)
	require.NoError(t, err, "NewSigner")
	obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	require.NoError(t, err, "Sign")

	t.Run("public", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			key  *mldsa.PublicKey
		}{
			{"typed-nil", nilPub},
			{"zero-value", zeroPub},
		} {
			t.Run(tc.name, func(t *testing.T) {
				jwk := &JSONWebKey{Key: tc.key}

				assert.False(t, jwk.Valid(), "Valid() = true; want false")
				assert.False(t, jwk.IsPublic(), "IsPublic() = true; want false")
				_, err := obj.Verify(tc.key)
				assert.Error(t, err, "Verify accepted the key")
				_, err = jwk.MarshalJSON()
				assert.Error(t, err, "MarshalJSON accepted the key")
				_, err = jwk.Thumbprint(crypto.SHA256)
				assert.Error(t, err, "Thumbprint accepted the key")
			})
		}
	})
}

func TestMLDSARoundtripJWS(t *testing.T) {
	serializers := []func(*JSONWebSignature) (string, error){
		func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
		func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
	}
	corrupter := func(obj *JSONWebSignature) {}

	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		for i, serializer := range serializers {
			t.Run(fmt.Sprintf("%s-serializer%d", alg, i), func(t *testing.T) {
				assert.NoError(t, RoundtripJWS(alg, serializer, corrupter, priv, priv.PublicKey(), "test_nonce"))
			})
		}
	}
}

func TestMLDSARoundtripJWSCorruptSignature(t *testing.T) {
	corrupter := func(obj *JSONWebSignature) {
		obj.Signatures[0].Signature[10]++
	}
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		err := RoundtripJWS(alg, func(obj *JSONWebSignature) (string, error) {
			return obj.CompactSerialize()
		}, corrupter, priv, priv.PublicKey(), "")
		assert.Error(t, err, "%s: corrupt signature verified successfully", alg)
	}
}

func TestMLDSASignerRejectsMismatchedAlg(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	for _, alg := range []SignatureAlgorithm{ML_DSA_65, ML_DSA_87, EdDSA, ES256} {
		_, err := NewSigner(SigningKey{Algorithm: alg, Key: priv}, nil)
		assert.Error(t, err, "NewSigner accepted an ML-DSA-44 key for %s", alg)
	}
}

func TestMLDSAVerifierRejectsMismatchedAlg(t *testing.T) {
	priv44 := mldsaTestKey(t, ML_DSA_44)
	priv65 := mldsaTestKey(t, ML_DSA_65)

	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44, Key: priv44}, nil)
	require.NoError(t, err, "NewSigner")
	obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	require.NoError(t, err, "Sign")
	msg, err := obj.CompactSerialize()
	require.NoError(t, err, "CompactSerialize")
	parsed, err := ParseSigned(msg, []SignatureAlgorithm{ML_DSA_44, ML_DSA_65})
	require.NoError(t, err, "ParseSigned")
	_, err = parsed.Verify(priv65.PublicKey())
	assert.Error(t, err, "an ML-DSA-65 key verified an ML-DSA-44 signature")
}

func TestMLDSAVerifyPayloadRejectsMismatchedAlg(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_65)
	payload := []byte("Lorem ipsum dolor sit amet")

	sig, err := priv.Sign(randReader, payload, crypto.Hash(0))
	require.NoError(t, err, "Sign")

	verifier, ok, err := mldsaVerifier(priv.PublicKey())
	if !ok || err != nil {
		require.Failf(t, "unexpected result", "mldsaVerifier(pub) = _, %v, %v; want _, true, nil", ok, err)
	}

	err = verifier.verifyPayload(payload, sig, ML_DSA_65)
	require.NoError(t, err, "verifyPayload(ML_DSA_65) failed on a matching key/signature pair")

	err = verifier.verifyPayload(payload, sig, ML_DSA_44)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "verifyPayload(ML_DSA_44) = %v; want ErrUnsupportedAlgorithm", err)
}

func TestMLDSASignPayloadRejectsMismatchedAlg(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_65)
	payload := []byte("Lorem ipsum dolor sit amet")

	signer := &mldsaPrivateKeySigner{privateKey: priv, alg: ML_DSA_65}

	_, err := signer.signPayload(payload, ML_DSA_65)
	require.NoError(t, err, "signPayload(ML_DSA_65) failed on a matching signer")

	_, err = signer.signPayload(payload, ML_DSA_44)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm, "signPayload(ML_DSA_44) = _, %v; want ErrUnsupportedAlgorithm", err)
}

func TestMLDSASignWithJSONWebKey(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		signingKey := JSONWebKey{Key: priv, KeyID: "test-kid", Algorithm: string(alg)}

		signer, err := NewSigner(SigningKey{Algorithm: alg, Key: signingKey}, nil)
		require.NoError(t, err, "%s: NewSigner with JSONWebKey", alg)
		obj, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
		require.NoError(t, err, "%s: Sign", alg)
		serialized, err := obj.CompactSerialize()
		require.NoError(t, err, "%s: CompactSerialize", alg)
		parsed, err := ParseSigned(serialized, []SignatureAlgorithm{alg})
		require.NoError(t, err, "%s: ParseSigned", alg)
		kid := parsed.Signatures[0].Header.KeyID
		assert.Equal(t, "test-kid", kid, "%s: KeyID = %q; want %q", alg, kid, "test-kid")
		_, err = parsed.Verify(&JSONWebKey{Key: priv.PublicKey()})
		assert.NoError(t, err, "%s: Verify with JSONWebKey", alg)
	}
}

func TestMLDSASignaturesAreRandomized(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44, Key: priv}, nil)
	require.NoError(t, err, "NewSigner")
	payload := []byte("Lorem ipsum dolor sit amet")
	first, err := signer.Sign(payload)
	require.NoError(t, err, "Sign")
	second, err := signer.Sign(payload)
	require.NoError(t, err, "Sign")
	assert.NotEqual(t, first.Signatures[0].Signature, second.Signatures[0].Signature, "two signatures over the same payload were identical; expected randomized signing")
}

func TestMLDSAMarshalPublicJWK(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		data, err := (&JSONWebKey{Key: priv.PublicKey()}).MarshalJSON()
		require.NoError(t, err, "%s: MarshalJSON", alg)

		var raw map[string]any
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err, "%s: unmarshal into map", alg)
		if raw["kty"] != "AKP" {
			assert.Failf(t, "unexpected result", "%s: kty = %v; want AKP", alg, raw["kty"])
		}

		// RFC 9964 makes alg REQUIRED, and it is derived from the key itself.
		if raw["alg"] != string(alg) {
			assert.Failf(t, "unexpected result", "%s: alg = %v; want %s", alg, raw["alg"], alg)
		}
		_, ok := raw["priv"]
		assert.False(t, ok, "%s: public JWK contains priv", alg)
		pub, err := base64.RawURLEncoding.DecodeString(raw["pub"].(string))
		require.NoError(t, err, "%s: pub is not raw base64url", alg)
		if len(pub) != mldsaExpectedPubSize[alg] {
			assert.Failf(t, "unexpected result", "%s: len(pub) = %d; want %d", alg, len(pub), mldsaExpectedPubSize[alg])
		}

		// Nothing from the EC/RSA/OKP vocabulary belongs on an AKP key.
		for _, member := range []string{"crv", "x", "y", "d", "n", "e", "k"} {
			_, ok := raw[member]
			assert.False(t, ok, "%s: AKP JWK unexpectedly contains %q", alg, member)
		}
	}
}

func TestMLDSAMarshalPrivateJWK(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		data, err := (&JSONWebKey{Key: priv}).MarshalJSON()
		require.NoError(t, err, "%s: MarshalJSON", alg)

		var raw map[string]any
		err = json.Unmarshal(data, &raw)
		require.NoError(t, err, "%s: unmarshal into map", alg)
		if raw["kty"] != "AKP" || raw["alg"] != string(alg) {
			assert.Failf(t, "unexpected result", "%s: kty/alg = %v/%v; want AKP/%s", alg, raw["kty"], raw["alg"], alg)
		}

		// RFC 9964: priv MUST be the seed and MUST be 32 bytes.
		seed, err := base64.RawURLEncoding.DecodeString(raw["priv"].(string))
		require.NoError(t, err, "%s: priv is not raw base64url", alg)
		assert.Len(t, seed, mldsa.PrivateKeySize, "%s: len(priv) = %d; want %d", alg, len(seed), mldsa.PrivateKeySize)
		assert.Equal(t, priv.Bytes(), seed, "%s: priv is not the key's seed", alg)

		// A private AKP JWK carries the public half too.
		pub, err := base64.RawURLEncoding.DecodeString(raw["pub"].(string))
		require.NoError(t, err, "%s: pub is not raw base64url", alg)
		assert.Equal(t, priv.PublicKey().Bytes(), pub, "%s: pub does not match the key's public half", alg)
	}
}

func TestMLDSAMarshalRejectsContradictoryAlgorithm(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)

	_, err := (&JSONWebKey{Key: priv, Algorithm: string(ML_DSA_44)}).MarshalJSON()
	assert.NoError(t, err, "MarshalJSON with matching Algorithm")

	_, err = (&JSONWebKey{Key: priv}).MarshalJSON()
	assert.NoError(t, err, "MarshalJSON with empty Algorithm")

	_, err = (&JSONWebKey{Key: priv, Algorithm: string(ML_DSA_87)}).MarshalJSON()
	assert.Error(t, err, "MarshalJSON accepted an Algorithm contradicting the key's parameter set")

	_, err = (&JSONWebKey{Key: priv, Algorithm: "EdDSA"}).MarshalJSON()
	assert.Error(t, err, "MarshalJSON accepted Algorithm=EdDSA on an ML-DSA key")
}

func TestMLDSAEmbedJWKWithContradictoryAlgorithm(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	signingKey := JSONWebKey{Key: priv, Algorithm: string(ML_DSA_87)}

	_, err := NewSigner(SigningKey{Algorithm: ML_DSA_44, Key: signingKey}, &SignerOptions{EmbedJWK: true})
	assert.ErrorIs(t, err, ErrUnsuitableKey, "NewSigner: got %v, want %v", err, ErrUnsuitableKey)
}

func TestMLDSAMarshalPreservesOtherKtyAlgHandling(t *testing.T) {
	data, err := (&JSONWebKey{Key: ed25519PublicKey, Algorithm: "EdDSA"}).MarshalJSON()
	require.NoError(t, err, "MarshalJSON")
	var raw map[string]any
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err, "unmarshal")
	assert.Equal(t, "EdDSA", raw["alg"])
}

func TestMLDSAJWKRoundtrip(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		for _, tc := range []struct {
			name string
			key  any
		}{
			{"public", priv.PublicKey()},
			{"private", priv},
		} {
			t.Run(fmt.Sprintf("%s-%s", alg, tc.name), func(t *testing.T) {
				data, err := (&JSONWebKey{Key: tc.key, KeyID: "kid-1", Use: "sig"}).MarshalJSON()
				require.NoError(t, err, "MarshalJSON")

				var parsed JSONWebKey
				err = parsed.UnmarshalJSON(data)
				require.NoError(t, err, "UnmarshalJSON")
				if parsed.KeyID != "kid-1" || parsed.Use != "sig" || parsed.Algorithm != string(alg) {
					assert.Failf(t, "unexpected result", "metadata lost: kid=%q use=%q alg=%q", parsed.KeyID, parsed.Use, parsed.Algorithm)
				}

				switch want := tc.key.(type) {
				case *mldsa.PublicKey:
					got, ok := parsed.Key.(*mldsa.PublicKey)
					require.True(t, ok, "parsed key is %T; want *mldsa.PublicKey", parsed.Key)
					assert.True(t, got.Equal(want), "parsed public key differs from the original")
				case *mldsa.PrivateKey:
					got, ok := parsed.Key.(*mldsa.PrivateKey)
					require.True(t, ok, "parsed key is %T; want *mldsa.PrivateKey", parsed.Key)
					assert.True(t, got.Equal(want), "parsed private key differs from the original")
				}
			})
		}
	}
}

// TestMLDSAParsedJWKSigns proves a parsed key is usable, not merely equal.
func TestMLDSAParsedJWKSigns(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_65)
	data, err := (&JSONWebKey{Key: priv}).MarshalJSON()
	require.NoError(t, err, "MarshalJSON")
	var parsed JSONWebKey
	err = parsed.UnmarshalJSON(data)
	require.NoError(t, err, "UnmarshalJSON")
	assert.NoError(t, RoundtripJWS(ML_DSA_65, func(obj *JSONWebSignature) (string, error) {
		return obj.CompactSerialize()
	}, func(*JSONWebSignature) {}, parsed.Key, priv.PublicKey(), ""))
}

func TestMLDSAParseJWKRejects(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	pub65 := base64.RawURLEncoding.EncodeToString(mldsaTestKey(t, ML_DSA_65).PublicKey().Bytes())
	seed := base64.RawURLEncoding.EncodeToString(priv.Bytes())
	otherSeed := base64.RawURLEncoding.EncodeToString(mldsaTestKey(t, ML_DSA_44).Bytes())

	for _, tc := range []struct {
		name string
		json string
	}{
		{
			"missing alg",
			fmt.Sprintf(`{"kty":"AKP","pub":%q}`, pub),
		},
		{
			"unrecognized alg",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-99","pub":%q}`, pub),
		},
		{
			"non ML-DSA alg",
			fmt.Sprintf(`{"kty":"AKP","alg":"EdDSA","pub":%q}`, pub),
		},
		{
			"neither pub nor priv",
			`{"kty":"AKP","alg":"ML-DSA-44"}`,
		},
		{
			"pub length disagrees with alg",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q}`, pub65),
		},
		{
			"priv is not 32 bytes",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"priv":%q}`, pub, pub),
		},
		{
			"priv without pub",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","priv":%q}`, seed),
		},
		{
			"pub disagrees with priv",
			fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"priv":%q}`, pub, otherSeed),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var key JSONWebKey
			err := key.UnmarshalJSON([]byte(tc.json))
			assert.Error(t, err, "UnmarshalJSON accepted %s", tc.name)
		})
	}
}

func TestMLDSAJWKWithCertificateChain(t *testing.T) {
	priv := mldsaTestKey(t, ML_DSA_44)
	other := mldsaTestKey(t, ML_DSA_44)

	newCert := func(key *mldsa.PrivateKey) string {
		t.Helper()
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "ml-dsa test"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
			SignatureAlgorithm:    x509.MLDSA44,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.PublicKey(), key)
		require.NoError(t, err, "CreateCertificate")
		return base64.StdEncoding.EncodeToString(der)
	}

	pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	// Matching chain: accepted.
	matching := fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"x5c":[%q]}`, pub, newCert(priv))
	var key JSONWebKey
	err := key.UnmarshalJSON([]byte(matching))
	assert.NoError(t, err, "UnmarshalJSON with a matching x5c")

	// Mismatched chain: rejected.
	mismatched := fmt.Sprintf(`{"kty":"AKP","alg":"ML-DSA-44","pub":%q,"x5c":[%q]}`, pub, newCert(other))
	var bad JSONWebKey
	err = bad.UnmarshalJSON([]byte(mismatched))
	assert.Error(t, err, "UnmarshalJSON accepted a JWK whose x5c leaf does not match pub")
}

func TestMLDSAThumbprint(t *testing.T) {
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)

		want := sha256.Sum256([]byte(fmt.Sprintf(
			`{"alg":"%s","kty":"AKP","pub":"%s"}`,
			alg,
			base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		)))

		got, err := (&JSONWebKey{Key: priv.PublicKey()}).Thumbprint(crypto.SHA256)
		require.NoError(t, err, "%s: Thumbprint", alg)
		if !bytes.Equal(got, want[:]) {
			assert.Failf(t, "unexpected result", "%s: thumbprint = %x; want %x", alg, got, want[:])
		}

		fromPriv, err := (&JSONWebKey{Key: priv}).Thumbprint(crypto.SHA256)
		require.NoError(t, err, "%s: Thumbprint of private key", alg)
		assert.Equal(t, got, fromPriv, "%s: private and public thumbprints differ", alg)
	}
}

func TestMLDSAThumbprintDiffersByAlg(t *testing.T) {
	seen := map[string]SignatureAlgorithm{}
	for _, alg := range mldsaAlgs {
		priv := mldsaTestKey(t, alg)
		tp, err := (&JSONWebKey{Key: priv.PublicKey()}).Thumbprint(crypto.SHA256)
		require.NoError(t, err, "%s: Thumbprint", alg)
		prev, ok := seen[string(tp)]
		assert.False(t, ok, "%s collided with %s", alg, prev)
		seen[string(tp)] = alg

		withoutAlg := sha256.Sum256([]byte(fmt.Sprintf(
			`{"kty":"AKP","pub":"%s"}`,
			base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		)))
		assert.NotEqual(t, tp, withoutAlg[:], "%s: thumbprint is unaffected by omitting alg from the template", alg)
	}
}

var mldsaExpectedPubSize = map[SignatureAlgorithm]int{
	ML_DSA_44: mldsa.MLDSA44PublicKeySize,
	ML_DSA_65: mldsa.MLDSA65PublicKeySize,
	ML_DSA_87: mldsa.MLDSA87PublicKeySize,
}

var mldsaAlgs = []SignatureAlgorithm{ML_DSA_44, ML_DSA_65, ML_DSA_87}

func mldsaTestKey(t *testing.T, alg SignatureAlgorithm) *mldsa.PrivateKey {
	t.Helper()
	params, ok := mldsaParamsFor(alg)
	require.True(t, ok, "mldsaParamsFor(%s): unknown algorithm", alg)
	key, err := mldsa.GenerateKey(params)
	require.NoError(t, err, "mldsa.GenerateKey(%s)", alg)
	return key
}
