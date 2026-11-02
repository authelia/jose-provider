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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/jose/json"
)

const trustedCA = `
-----BEGIN CERTIFICATE-----
MIIE8DCCAtigAwIBAgIJAPgBgSSm5PSpMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV
BAMMCVRydXN0ZWRDQTAeFw0yMDEwMDQyMjU0MzlaFw00MDEwMDQyMjU0MzlaMBQx
EjAQBgNVBAMMCVRydXN0ZWRDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBAJ+o4csEF8uhudNfBgOilhJbJT4D+gLTJT2l7+YEaRnJsyKnaaMYTZl3j+6z
8eRPCIx0wkeVvy9H0XXARkXPylycpFrFdOOE+jG7n/KpglOgD4cnpJEc2cZOGnxi
d1EiVEoFS9iD1L+SZG0XLfczfGCi970lK1UfBkADrjxXPdUmml+LFlQbLwdjw29e
b8heaYep3ltXpyfy2W0mgLakqV+mWqPzcp4dWjohSrOWr/iZSWTVLKlXyKvj3nfC
lcXU5FqDSlU5m6tbxhfscEvG2n12TzpGTNSez7my3qxNaAFf1rd/+RvJYjJ4gelH
O9ZF9POqOxdoRgZca2SQetRaUlrYbJTY9cjKEJLloo83I65vWDqgMREChzpMorKz
ZCeqCVgsgAdo75kiCW1fHY6MvBFk2x9kfZqwv/Dp+vyv22bOVa7ob84CEWbRYMIt
wCXRXrewAkvCHFvB6Uoz2Qn2c+3jWzlyRNCucfaPtWnNzRaG6lVm9ieucQI/+Ij4
XwuZmmPzOAvKlXadVXNlnsExkrAabc6UJEyqKI7raSeJaR/8RLLfxTDSv3UuWY8v
I2QMdS1f6fC8VJKTYMfbdnIw4RQ9Eqi2EmNPgJ4I2mTilG12pRxl/dvfFTl/7/TM
Mu6jCLNvJnm3B96at1Y4evWoee51EcvpkNnwotyPLtJFpEMLAgMBAAGjRTBDMB0G
A1UdDgQWBBTJ8bqL9u+G1ykEpl9uakSgZGq3JDASBgNVHRMBAf8ECDAGAQH/AgEB
MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAB9WBvqUM+tM+1JAS
YmUmRKjYlrKUYwNTzgrAyyiYLWzp9cmcw+3hbAjDV0Lu1Im8QQ0eRdq2H8103JYd
+nJJx+zlJ04s3pms02uZf8s05XJPSqlYb03uyfZ5uQcOAsRAPHeXaxEmZ/K6PGqO
14O3anXb5u+Qq2cb7DGG/Qcek8iX8vI5RqxvLGOOD9z9mpqE9M6aTsjuBVSLM3aQ
yIIkRk3deXiOfZd8d+0pShKgVBSrAC8c7A+Yps/r/vSGmN8L+LDoNzfx4NaPLBzu
dgiKVpYYgjFEnDzYItWpyxkPVjfMxPEQkz8choJaYNuoROpZtEnSFb4MFHlYGqhO
ZYETsYL3BRCHp0WysA3KuXTyA2Tmr+503Xw0btO2ieGEOCe3v/Yc7WGQX3RRAdci
2TkBISG6QlH5FzeV11hPriKEMSFHFdJvVrtRORtkGPeE6DUjHQ8MSK8Vm0niKT5P
l9GLvIrBN00Pa+YUX0j1xaCY0aj0oxKDFIdyWTn6aR/q9M7CfW6H0fNjPu56+jit
q+yQijumIkI5MTlbj0ja51yN62/tNhpTZx/NXpWjgZ+S/668/BJ2veV99PGuQCss
jlhHfN8RbHaPuKTKLLslkTvtpIYTc6F9TmcnVAdyKxN8e1XHcV4WrIOzgegVE4IF
48TF8WeXgGnsH4Bvob3cZcqWA+w=
-----END CERTIFICATE-----`

const intermediateCA = `
-----BEGIN CERTIFICATE-----
MIIEDzCCAfegAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVHJ1
c3RlZENBMB4XDTIwMTAwNDIzMDMzM1oXDTQwMTAwNDIzMDMzM1owGTEXMBUGA1UE
AwwOSW50ZXJtZWRpYXRlQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDiKADoUoaNvD4yCLPySuPR1saLWHNRlt2nqbd7smwB1quNKnKwAKKnLyaBUHIC
FrQjCTA7IF7KUndVU0vutMFzn6hKuliZMYbwDQgx6x8u34m8Ar8cAg/AJPgT5Kk6
Ds8soUaTzRG/GXVjGll0ArjRp97LmOW1Tc53R4YJji6eTThgb4Al6XDou2AeEMNY
C46yqafwzOvHOnzSQwy8IwdcFjNKry15pvutIK3UhZscAmfbNEN5ou3miWcz3PuV
GORxKAqlA4mYoJWE2AF52fgNTYcTFCDdiThaFSBzgqEgFoDzzROhf1B+/bSJ4gUL
K9YQxpXVmt8/tlvXjNygDj1LAgMBAAGjZjBkMB0GA1UdDgQWBBTZZOBbEfV70Ocm
9RIM16yhAw4SyjAfBgNVHSMEGDAWgBTJ8bqL9u+G1ykEpl9uakSgZGq3JDASBgNV
HRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOC
AgEADfEtLh3YDabrTsx+KmJ1f8ybwdltgI3gPiubd5RcYcoO3Pd33/INJDMkJYfL
CrSDLI5Y94szOUhkP/rSwrUgJErnPSPUEW11GgA230d7vjc3bFJO/bPb2ZAwm/eC
7dMMyyDH/2Wty7h7SOuXXJljZYIvuavJymZxsmkDAu7MtdntHVLr5bruEYvM9IKa
d9YZSchRP1Q3kIZuTmNvBgLGwrVw/UcOpczajULNNzPUNPDFs9Zo04tx/YF1R1fO
GUhif13DMk+6JU7zUXZL3iqOSkxBRrlMQX6nKAQ68cMqO2UsrfXBqH5xm3O9+Nxs
fN3CkkTcyBcvVFMaMe0670lCh3DcFOMDt2YdlqS5tEsBn3TdOFKSjv2dVnT2eeXc
q5IvuC4nkEXzZDROfQVrnraBhHOiyLAlfwhA1LHZGlJfNZaWRDdXHKV+pIMr2JyO
v/hf9aaWzjwyy7FJwn3yrEwHGfBgx0vgKPj6l6N8qxQ6l1XMyANx4ExlpXfffx+C
PWV9eeMi4Wh6V9641LesQnlOGgL5R03jQRjaicp3nvzsNElDEgPq0s9PE8s6weFK
Bz5ykrw/Gg4QWmw6MfwjOX5Fu1oJF9ABoCFD5umvKhpoJkcT8aYM0+E1xiEAx64u
Wq2b2GCGP4wMEZuqCcE72fiue295ovPkNsbEjTQk/ijWza0=
-----END CERTIFICATE-----`

func TestParseEmptySigned(t *testing.T) {
	_, err := ParseSigned("", []SignatureAlgorithm{HS256})
	assert.ErrorIs(t, err, errEmptyInput, "parsing empty input: got %s, want %s", err, errEmptyInput)

	_, err = ParseSignedCompact("", []SignatureAlgorithm{HS256})
	assert.ErrorIs(t, err, errEmptyInput, "parsing empty input: got %s, want %s", err, errEmptyInput)

	_, err = ParseSignedJSON("", []SignatureAlgorithm{HS256})
	assert.ErrorIs(t, err, errEmptyInput, "parsing empty input: got %s, want %s", err, errEmptyInput)

	_, err = ParseDetached("", []byte{}, []SignatureAlgorithm{HS256})
	assert.ErrorIs(t, err, errEmptyInput, "parsing empty input: got %s, want %s", err, errEmptyInput)
}

func TestEmbeddedHMAC(t *testing.T) {
	// protected: {"alg":"HS256", "jwk":{"kty":"oct", "k":"MTEx"}}, aka HMAC key.
	msg := `{"payload":"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ","protected":"eyJhbGciOiJIUzI1NiIsICJqd2siOnsia3R5Ijoib2N0IiwgImsiOiJNVEV4In19","signature":"lvo41ZZsuHwQvSh0uJtEXRR3vmuBJ7in6qMoD7p9jyo"}`

	_, err := ParseSigned(msg, []SignatureAlgorithm{HS256})
	assert.Error(t, err, "should not allow parsing JWS with embedded JWK with HMAC key")
}

func TestCompactParseJWS(t *testing.T) {
	// Should parse
	msg := "eyJhbGciOiJYWVoifQ.cGF5bG9hZA.c2lnbmF0dXJl"
	_, err := ParseSigned(msg, []SignatureAlgorithm{SignatureAlgorithm("XYZ")})
	assert.NoError(t, err, "Unable to parse valid message")

	// Should parse (detached signature missing payload)
	msg = "eyJhbGciOiJYWVoifQ..c2lnbmF0dXJl"
	_, err = ParseSigned(msg, []SignatureAlgorithm{SignatureAlgorithm("XYZ")})
	assert.NoError(t, err, "Unable to parse valid message")

	// Messages that should fail to parse
	failures := []string{
		// Not enough parts
		"eyJhbGciOiJYWVoifQ.cGF5bG9hZA",
		// Invalid signature
		"eyJhbGciOiJYWVoifQ.cGF5bG9hZA.////",
		// Invalid payload
		"eyJhbGciOiJYWVoifQ.////.c2lnbmF0dXJl",
		// Invalid header
		"////.eyJhbGciOiJYWVoifQ.c2lnbmF0dXJl",
		// Invalid header
		"cGF5bG9hZA.cGF5bG9hZA.c2lnbmF0dXJl",
		// Too many parts
		"eyJhbGciOiJYWVoifQ.cGF5bG9hZA.c2lnbmF0dXJl.....................................................",
		"eyJhbGciOiJYWVoifQ.cGF5bG9hZA.c2lnbmF0dXJl.cGF5bG9hZA.cGF5bG9hZA.cGF5bG9hZA....................",
	}

	for i := range failures {
		_, err = ParseSigned(failures[i], []SignatureAlgorithm{SignatureAlgorithm("XYZ")})
		assert.Error(t, err, "Able to parse invalid message")
	}
}

func TestFullParseJWS(t *testing.T) {
	// Messages that should succeed to parse
	successes := []string{
		`{
		  "payload":"CUJD",
		  "signatures":[
			{"protected":"eyJhbGciOiJBQkMifQo","header":{"kid":"XYZ"},"signature":"CUJD"},
			{"protected":"eyJhbGciOiJBQkMifQo","signature":"CUJD"}
		  ]}`,
	}

	for i := range successes {
		_, err := ParseSigned(successes[i], []SignatureAlgorithm{SignatureAlgorithm("ABC")})
		assert.NoError(t, err)
	}

	// Messages that should fail to parse
	failures := []string{
		// Empty
		"{}",
		// Flattened member alongside signatures (RFC 7515 Section 7.2.2)
		`{
		  "header":{"alg":"XYZ"},
		  "payload":"CUJD",
		  "signatures":[
			{"protected":"eyJhbGciOiJBQkMifQo","header":{"kid":"XYZ"},"signature":"CUJD"},
			{"protected":"eyJhbGciOiJBQkMifQo","signature":"CUJD"}
		  ]}`,
		// Invalid JSON
		"{XX",
		// Invalid protected header
		"{\"payload\":\"CUJD\",\"signatures\":[{\"protected\":\"CUJD\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}]}",
		// Invalid protected header
		"{\"payload\":\"CUJD\",\"protected\":\"CUJD\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}",
		// Invalid protected header
		"{\"payload\":\"CUJD\",\"signatures\":[{\"protected\":\"###\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}]}",
		// Invalid payload
		"{\"payload\":\"###\",\"signatures\":[{\"protected\":\"CUJD\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"CUJD\"}]}",
		// Invalid payload
		"{\"payload\":\"CUJD\",\"signatures\":[{\"protected\":\"e30\",\"header\":{\"kid\":\"XYZ\"},\"signature\":\"###\"}]}",
	}

	for i := range failures {
		_, err := ParseSigned(failures[i], []SignatureAlgorithm{SignatureAlgorithm("XYZ")})
		assert.Error(t, err)
	}
}

func TestRejectUnprotectedJWSNonce(t *testing.T) {
	// No need to test compact, since that's always protected

	// Flattened JSON
	input := `{
		"header": { "nonce": "should-cause-an-error" },
		"payload": "QUJD",
		"signature": "QUJD"
	}`
	_, err := ParseSigned(input, []SignatureAlgorithm{SignatureAlgorithm("XYZ")})
	assert.Same(t, ErrUnprotectedNonce, err, "Improper error for unprotected nonce")

	// Full JSON
	input = `{
		"payload": "QUJD",
 		"signatures": [{
 			"header": { "nonce": "should-cause-an-error" },
			"signature": "QUJD"
		}]
	}`
	_, err = ParseSigned(input, []SignatureAlgorithm{SignatureAlgorithm("XYZ")})
	assert.Same(t, ErrUnprotectedNonce, err, "Improper error for unprotected nonce")
}

func TestParseSignedJSONDoesNotRewriteMemberNames(t *testing.T) {
	payload := []byte(`{"resource":"newAccount"}`)
	protected := rawHeader{}
	err := protected.set(headerAlgorithm, RS256)
	require.NoError(t, err, "set alg")
	protectedJSON, err := json.Marshal(protected)
	require.NoError(t, err, "marshal protected")
	protectedB64 := newBuffer(protectedJSON).base64()
	payloadB64 := newBuffer(payload).base64()
	signingInput := []byte(protectedB64 + "." + payloadB64)
	signature, err := rsaDecrypterSigner{privateKey: rsaTestKey}.signPayload(signingInput, RS256)
	require.NoError(t, err, "sign payload")

	jwkJSON, err := json.Marshal(JSONWebKey{Key: &rsaTestKey.PublicKey})
	require.NoError(t, err, "marshal jwk")
	raw := `{"payload":"` + payloadB64 +
		`","protected":"` + protectedB64 +
		`","hea der":{"jwk":` + string(jwkJSON) +
		`,"url":"https://example.test/acme/new-account"}` +
		`,"signature":"` + newBuffer(signature.Signature).base64() + `"}`

	parsed, err := ParseSigned(raw, []SignatureAlgorithm{RS256})
	require.NoError(t, err, "ParseSigned")
	header := parsed.Signatures[0].Header
	require.Nil(t, header.JSONWebKey, "ParseSigned exposed a JWK from a whitespace-mutated member name")
	_, ok := header.ExtraHeaders[HeaderKey("url")]
	require.False(t, ok, "ParseSigned exposed a header from a whitespace-mutated member name")

	verified, err := parsed.Verify(&rsaTestKey.PublicKey)
	require.NoError(t, err, "Verify")
	require.Equal(t, string(payload), string(verified), "verified payload = %q, want %q", verified, payload)
}

func TestVerifyFlattenedWithIncludedUnprotectedKey(t *testing.T) {
	input := `{
			"header": {
					"alg": "RS256",
					"jwk": {
							"e": "AQAB",
							"kty": "RSA",
							"n": "tSwgy3ORGvc7YJI9B2qqkelZRUC6F1S5NwXFvM4w5-M0TsxbFsH5UH6adigV0jzsDJ5imAechcSoOhAh9POceCbPN1sTNwLpNbOLiQQ7RD5mY_pSUHWXNmS9R4NZ3t2fQAzPeW7jOfF0LKuJRGkekx6tXP1uSnNibgpJULNc4208dgBaCHo3mvaE2HV2GmVl1yxwWX5QZZkGQGjNDZYnjFfa2DKVvFs0QbAk21ROm594kAxlRlMMrvqlf24Eq4ERO0ptzpZgm_3j_e4hGRD39gJS7kAzK-j2cacFQ5Qi2Y6wZI2p-FCq_wiYsfEAIkATPBiLKl_6d_Jfcvs_impcXQ"
					}
			},
			"payload": "Zm9vCg",
			"signature": "hRt2eYqBd_MyMRNIh8PEIACoFtmBi7BHTLBaAhpSU6zyDAFdEBaX7us4VB9Vo1afOL03Q8iuoRA0AT4akdV_mQTAQ_jhTcVOAeXPr0tB8b8Q11UPQ0tXJYmU4spAW2SapJIvO50ntUaqU05kZd0qw8-noH1Lja-aNnU-tQII4iYVvlTiRJ5g8_CADsvJqOk6FcHuo2mG643TRnhkAxUtazvHyIHeXMxydMMSrpwUwzMtln4ZJYBNx4QGEq6OhpAD_VSp-w8Lq5HOwGQoNs0bPxH1SGrArt67LFQBfjlVr94E1sn26p4vigXm83nJdNhWAMHHE9iV67xN-r29LT-FjA"
	}`

	jws, err := ParseSigned(input, []SignatureAlgorithm{RS256})
	require.NoError(t, err, "Unable to parse valid message")
	assert.Len(t, jws.Signatures, 1, "Too many or too few signatures.")
	sig := jws.Signatures[0]
	assert.NotNil(t, sig.Header.JSONWebKey, "No JWK in signature header.")
	payload, err := jws.Verify(sig.Header.JSONWebKey)
	assert.NoError(t, err, "Signature did not validate")
	assert.Equal(t, "foo\n", string(payload), "Payload was incorrect: '%s' should have been 'foo\\n'", string(payload))
}

// Test verification of a detached signature
func TestDetachedVerifyJWS(t *testing.T) {
	rsaPublicKey, err := x509.ParsePKIXPublicKey(fromBase64Bytes(`
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3aLSGwbeX0ZA2Ha+EvELaIFGzO
		91+Q15JQc/tdGdCgGW3XAbrh7ZUhDh1XKzbs+UOQxqn3Eq4YOx18IG0WsJSuCaHQIxnDlZ
		t/GP8WLwjMC0izlJLm2SyfM/EEoNpmTC3w6MQ2dHK7SZ9Zoq+sKijQd+V7CYdr8zHMpDrd
		NKoEcR0HjmvzzdMoUChhkGH5TaNbZyollULTggepaYUKS8QphqdSDMWiSetKG+g6V87lv6
		CVYyK1FF6g7Esp5OOj5pNn3/bmF+7V+b7TvK91NCIlURCjE9toRgNoIP4TDnWRn/vvfZ3G
		zNrtWmlizqz3r5KdvIs71ahWgMUSD4wfazrwIDAQAB`))
	require.NoError(t, err)

	sampleMessages := []string{
		"eyJhbGciOiJSUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.YHX849fvekz6wJGeyqnQhFqyHFcUXNJKj3o2w3ddR46YLlsCopUJrlifRU_ZuTWzpYxt5oC--T2eoqMhlCvltSWrE5_1_EumqiMfAYsZULx9E6Jns7q3w7mttonYFSIh7aR3-yg2HMMfTCgoAY1y_AZ4VjXwHDcZ5gu1oZDYgvZF4uXtCmwT6e5YtR1m8abiWPF8BgoTG_BD3KV6ClLj_QQiNFdfdxAMDw7vKVOKG1T7BFtz6cDs2Q3ILS4To5E2IjcVSSYS8mi77EitCrWmrqbK_G3WCdKeUFGnMnyuKXaCDy_7FLpAZ6Z5RomRr5iskXeJZdZqIKcJV8zl4fpsPA",
		"eyJhbGciOiJSUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.meyfoOTjAAjXHFYiNlU7EEnsYtbeUYeEglK6BL_cxISEr2YAGLr1Gwnn2HnucTnH6YilyRio7ZC1ohy_ZojzmaljPHqpr8kn1iqNFu9nFE2M16ZPgJi38-PGzppcDNliyzOQO-c7L-eA-v8Gfww5uyRaOJdiWg-hUJmeGBIngPIeLtSVmhJtz8oTeqeNdUOqQv7f7VRCuvagLhW1PcEM91VUS-gS0WEUXoXWZ2lp91No0v1O24izgX3__FKiX_16XhrOfAgJ82F61vjbTIQYwhexHPZyYTlXYt_scNRzFGhSKeGFin4zVdFLOXWJqKWdUd5IrDP5Nya3FSoWbWDXAg",
	}

	for _, msg := range sampleMessages {
		obj, err := ParseSigned(msg, []SignatureAlgorithm{RS256, RS384})
		if !assert.NoError(t, err, "unable to parse message msg=%v", msg) {
			continue
		}
		payload := obj.payload
		obj.payload = nil
		err = obj.DetachedVerify(payload, rsaPublicKey)
		if !assert.NoError(t, err, "unable to verify message msg=%v", msg) {
			continue
		}
		idx, _, err := obj.DetachedVerifyMulti(payload, rsaPublicKey)
		if idx != 0 || err != nil {
			assert.Failf(t, "unexpected result", "unable to verify message msg=%v err=%v", msg, err)
			continue
		}
	}
}

func TestVerifyFlattenedWithPrivateProtected(t *testing.T) {
	// The protected field contains a Private Header Parameter name, per
	// https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
	// Base64-decoded, it's '{"nonce":"8HIepUNFZUa-exKTrXVf4g"}'
	input := `{"header":{"alg":"RS256","jwk":{"kty":"RSA","n":"7ixeydcbxxppzxrBphrW1atUiEZqTpiHDpI-79olav5XxAgWolHmVsJyxzoZXRxmtED8PF9-EICZWBGdSAL9ZTD0hLUCIsPcpdgT_LqNW3Sh2b2caPL2hbMF7vsXvnCGg9varpnHWuYTyRrCLUF9vM7ES-V3VCYTa7LcCSRm56Gg9r19qar43Z9kIKBBxpgt723v2cC4bmLmoAX2s217ou3uCpCXGLOeV_BesG4--Nl3pso1VhCfO85wEWjmW6lbv7Kg4d7Jdkv5DjDZfJ086fkEAYZVYGRpIgAvJBH3d3yKDCrSByUEud1bWuFjQBmMaeYOrVDXO_mbYg5PwUDMhw","e":"AQAB"}},"protected":"eyJub25jZSI6IjhISWVwVU5GWlVhLWV4S1RyWFZmNGcifQ","payload":"eyJjb250YWN0IjpbIm1haWx0bzpmb29AYmFyLmNvbSJdfQ","signature":"AyvVGMgXsQ1zTdXrZxE_gyO63pQgotL1KbI7gv6Wi8I7NRy0iAOkDAkWcTQT9pcCYApJ04lXfEDZfP5i0XgcFUm_6spxi5mFBZU-NemKcvK9dUiAbXvb4hB3GnaZtZiuVnMQUb_ku4DOaFFKbteA6gOYCnED_x7v0kAPHIYrQnvIa-KZ6pTajbV9348zgh9TL7NgGIIsTcMHd-Jatr4z1LQ0ubGa8tS300hoDhVzfoDQaEetYjCo1drR1RmdEN1SIzXdHOHfubjA3ZZRbrF_AJnNKpRRoIwzu1VayOhRmdy1qVSQZq_tENF4VrQFycEL7DhG7JLoXC4T2p1urwMlsw"}`

	jws, err := ParseSigned(input, []SignatureAlgorithm{RS256})
	assert.NoError(t, err, "Unable to parse valid message.")
	assert.Len(t, jws.Signatures, 1, "Too many or too few signatures.")
	sig := jws.Signatures[0]
	assert.NotNil(t, sig.Header.JSONWebKey, "No JWK in signature header.")
	payload, err := jws.Verify(sig.Header.JSONWebKey)
	assert.NoError(t, err, "Signature did not validate")
	expected := "{\"contact\":[\"mailto:foo@bar.com\"]}"
	assert.Equal(t, expected, string(payload), "Payload was incorrect: '%s' should have been '%s'", string(payload), expected)
}

// Test vectors generated with nimbus-jose-jwt
func TestSampleNimbusJWSMessagesRSA(t *testing.T) {
	rsaPublicKey, err := x509.ParsePKIXPublicKey(fromBase64Bytes(`
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3aLSGwbeX0ZA2Ha+EvELaIFGzO
		91+Q15JQc/tdGdCgGW3XAbrh7ZUhDh1XKzbs+UOQxqn3Eq4YOx18IG0WsJSuCaHQIxnDlZ
		t/GP8WLwjMC0izlJLm2SyfM/EEoNpmTC3w6MQ2dHK7SZ9Zoq+sKijQd+V7CYdr8zHMpDrd
		NKoEcR0HjmvzzdMoUChhkGH5TaNbZyollULTggepaYUKS8QphqdSDMWiSetKG+g6V87lv6
		CVYyK1FF6g7Esp5OOj5pNn3/bmF+7V+b7TvK91NCIlURCjE9toRgNoIP4TDnWRn/vvfZ3G
		zNrtWmlizqz3r5KdvIs71ahWgMUSD4wfazrwIDAQAB`))
	if err != nil {
		panic(err)
	}

	rsaSampleMessages := []string{
		"eyJhbGciOiJSUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.YHX849fvekz6wJGeyqnQhFqyHFcUXNJKj3o2w3ddR46YLlsCopUJrlifRU_ZuTWzpYxt5oC--T2eoqMhlCvltSWrE5_1_EumqiMfAYsZULx9E6Jns7q3w7mttonYFSIh7aR3-yg2HMMfTCgoAY1y_AZ4VjXwHDcZ5gu1oZDYgvZF4uXtCmwT6e5YtR1m8abiWPF8BgoTG_BD3KV6ClLj_QQiNFdfdxAMDw7vKVOKG1T7BFtz6cDs2Q3ILS4To5E2IjcVSSYS8mi77EitCrWmrqbK_G3WCdKeUFGnMnyuKXaCDy_7FLpAZ6Z5RomRr5iskXeJZdZqIKcJV8zl4fpsPA",
		"eyJhbGciOiJSUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.meyfoOTjAAjXHFYiNlU7EEnsYtbeUYeEglK6BL_cxISEr2YAGLr1Gwnn2HnucTnH6YilyRio7ZC1ohy_ZojzmaljPHqpr8kn1iqNFu9nFE2M16ZPgJi38-PGzppcDNliyzOQO-c7L-eA-v8Gfww5uyRaOJdiWg-hUJmeGBIngPIeLtSVmhJtz8oTeqeNdUOqQv7f7VRCuvagLhW1PcEM91VUS-gS0WEUXoXWZ2lp91No0v1O24izgX3__FKiX_16XhrOfAgJ82F61vjbTIQYwhexHPZyYTlXYt_scNRzFGhSKeGFin4zVdFLOXWJqKWdUd5IrDP5Nya3FSoWbWDXAg",
		"eyJhbGciOiJSUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.rQPz0PDh8KyE2AX6JorgI0MLwv-qi1tcWlz6tuZuWQG1hdrlzq5tR1tQg1evYNc_SDDX87DWTSKXT7JEqhKoFixLfZa13IJrOc7FB8r5ZLx7OwOBC4F--OWrvxMA9Y3MTJjPN3FemQePUo-na2vNUZv-YgkcbuOgbO3hTxwQ7j1JGuqy-YutXOFnccdXvntp3t8zYZ4Mg1It_IyL9pzgGqHIEmMV1pCFGHsDa-wStB4ffmdhrADdYZc0q_SvxUdobyC_XzZCz9ENzGIhgwYxyyrqg7kjqUGoKmCLmoSlUFW7goTk9IC5SXdUyLPuESxOWNfHoRClGav230GYjPFQFA",
		"eyJhbGciOiJQUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.UTtxjsv_6x4CdlAmZfAW6Lun3byMjJbcwRp_OlPH2W4MZaZar7aql052mIB_ddK45O9VUz2aphYVRvKPZY8WHmvlTUU30bk0z_cDJRYB9eIJVMOiRCYj0oNkz1iEZqsP0YgngxwuUDv4Q4A6aJ0Bo5E_rZo3AnrVHMHUjPp_ZRRSBFs30tQma1qQ0ApK4Gxk0XYCYAcxIv99e78vldVRaGzjEZmQeAVZx4tGcqZP20vG1L84nlhSGnOuZ0FhR8UjRFLXuob6M7EqtMRoqPgRYw47EI3fYBdeSivAg98E5S8R7R1NJc7ef-l03RvfUSY0S3_zBq_4PlHK6A-2kHb__w",
		"eyJhbGciOiJSUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.meyfoOTjAAjXHFYiNlU7EEnsYtbeUYeEglK6BL_cxISEr2YAGLr1Gwnn2HnucTnH6YilyRio7ZC1ohy_ZojzmaljPHqpr8kn1iqNFu9nFE2M16ZPgJi38-PGzppcDNliyzOQO-c7L-eA-v8Gfww5uyRaOJdiWg-hUJmeGBIngPIeLtSVmhJtz8oTeqeNdUOqQv7f7VRCuvagLhW1PcEM91VUS-gS0WEUXoXWZ2lp91No0v1O24izgX3__FKiX_16XhrOfAgJ82F61vjbTIQYwhexHPZyYTlXYt_scNRzFGhSKeGFin4zVdFLOXWJqKWdUd5IrDP5Nya3FSoWbWDXAg",
		"eyJhbGciOiJSUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.rQPz0PDh8KyE2AX6JorgI0MLwv-qi1tcWlz6tuZuWQG1hdrlzq5tR1tQg1evYNc_SDDX87DWTSKXT7JEqhKoFixLfZa13IJrOc7FB8r5ZLx7OwOBC4F--OWrvxMA9Y3MTJjPN3FemQePUo-na2vNUZv-YgkcbuOgbO3hTxwQ7j1JGuqy-YutXOFnccdXvntp3t8zYZ4Mg1It_IyL9pzgGqHIEmMV1pCFGHsDa-wStB4ffmdhrADdYZc0q_SvxUdobyC_XzZCz9ENzGIhgwYxyyrqg7kjqUGoKmCLmoSlUFW7goTk9IC5SXdUyLPuESxOWNfHoRClGav230GYjPFQFA",
	}

	for _, msg := range rsaSampleMessages {
		obj, err := ParseSigned(msg, []SignatureAlgorithm{RS256, RS384, RS512, PS256})
		if !assert.NoError(t, err, "unable to parse message msg=%v", msg) {
			continue
		}
		payload, err := obj.Verify(rsaPublicKey)
		if !assert.NoError(t, err, "unable to verify message msg=%v", msg) {
			continue
		}
		assert.Equal(t, "Lorem ipsum dolor sit amet", string(payload), "payload is not what we expected for msg msg=%v", msg)
	}
}

// Test vectors generated with nimbus-jose-jwt
func TestSampleNimbusJWSMessagesEC(t *testing.T) {
	ecPublicKeyP256, err := x509.ParsePKIXPublicKey(fromBase64Bytes("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIg62jq6FyL1otEj9Up7S35BUrwGF9TVrAzrrY1rHUKZqYIGEg67u/imjgadVcr7y9Q32I0gB8W8FHqbqt696rA=="))
	if err != nil {
		panic(err)
	}
	ecPublicKeyP384, err := x509.ParsePKIXPublicKey(fromBase64Bytes("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPXsVlqCtN2oTY+F+hFZm3M0ldYpb7IeeJM5wYmT0k1RaqzBFDhDMNnYK5Q5x+OyssZrAtHgYDFw02AVJhhng/eHRp7mqmL/vI3wbxJtrLKYldIbBA+9fYBQcKeibjlu5"))
	if err != nil {
		panic(err)
	}
	ecPublicKeyP521, err := x509.ParsePKIXPublicKey(fromBase64Bytes("MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAa2w3MMJ5FWD6tSf68G+Wy5jIhWXOD3IA7pE5IC/myQzo1lWcD8KS57SM6nm4POtPcxyLmDhL7FLuh8DKoIZyvtAAdK8+tOQP7XXRlT2bkvzIuazp05It3TAPu00YzTIpKfDlc19Y1lvf7etrbFqhShD92B+hHmhT4ddrdbPCBDW8hvU="))
	if err != nil {
		panic(err)
	}

	ecPublicKeys := []any{ecPublicKeyP256, ecPublicKeyP384, ecPublicKeyP521}

	ecSampleMessages := []string{
		"eyJhbGciOiJFUzI1NiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.MEWJVlvGRQyzMEGOYm4rwuiwxrX-6LjnlbaRDAuhwmnBm2Gtn7pRpGXRTMFZUXsSGDz2L1p-Hz1qn8j9bFIBtQ",
		"eyJhbGciOiJFUzM4NCJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.nbdjPnJPYQtVNNdBIx8-KbFKplTxrz-hnW5UNhYUY7SBkwHK4NZnqc2Lv4DXoA0aWHq9eiypgOh1kmyPWGEmqKAHUx0xdIEkBoHk3ZsbmhOQuq2jL_wcMUG6nTWNhLrB",
		"eyJhbGciOiJFUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.AeYNFC1rwIgQv-5fwd8iRyYzvTaSCYTEICepgu9gRId-IW99kbSVY7yH0MvrQnqI-a0L8zwKWDR35fW5dukPAYRkADp3Y1lzqdShFcEFziUVGo46vqbiSajmKFrjBktJcCsfjKSaLHwxErF-T10YYPCQFHWb2nXJOOI3CZfACYqgO84g",
	}

	for i, msg := range ecSampleMessages {
		obj, err := ParseSigned(msg, []SignatureAlgorithm{ES256, ES384, ES512})
		if !assert.NoError(t, err, "unable to parse message msg=%v", msg) {
			continue
		}
		payload, err := obj.Verify(ecPublicKeys[i])
		if !assert.NoError(t, err, "unable to verify message msg=%v", msg) {
			continue
		}
		assert.Equal(t, "Lorem ipsum dolor sit amet", string(payload), "payload is not what we expected for msg msg=%v", msg)
	}
}

func TestHeaderFieldsCompact(t *testing.T) {
	msg := "eyJhbGciOiJFUzUxMiJ9.TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ.AeYNFC1rwIgQv-5fwd8iRyYzvTaSCYTEICepgu9gRId-IW99kbSVY7yH0MvrQnqI-a0L8zwKWDR35fW5dukPAYRkADp3Y1lzqdShFcEFziUVGo46vqbiSajmKFrjBktJcCsfjKSaLHwxErF-T10YYPCQFHWb2nXJOOI3CZfACYqgO84g"

	obj, err := ParseSigned(msg, []SignatureAlgorithm{ES512})
	require.NoError(t, err, "unable to parse message msg=%v", msg)
	assert.Equal(t, "ES512", obj.Signatures[0].Header.Algorithm, "merged header did not contain expected alg value")
	assert.Equal(t, "ES512", obj.Signatures[0].Protected.Algorithm, "protected header did not contain expected alg value")
	assert.Equal(t, "", obj.Signatures[0].Unprotected.Algorithm, "unprotected header contained an alg value")
}

func TestHeaderFieldsFull(t *testing.T) {
	msg := `{"payload":"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ","protected":"eyJhbGciOiJFUzUxMiJ9","header":{"custom":"test"},"signature":"AeYNFC1rwIgQv-5fwd8iRyYzvTaSCYTEICepgu9gRId-IW99kbSVY7yH0MvrQnqI-a0L8zwKWDR35fW5dukPAYRkADp3Y1lzqdShFcEFziUVGo46vqbiSajmKFrjBktJcCsfjKSaLHwxErF-T10YYPCQFHWb2nXJOOI3CZfACYqgO84g"}`

	obj, err := ParseSigned(msg, []SignatureAlgorithm{ES512})
	require.NoError(t, err, "unable to parse message msg=%v", msg)
	assert.Equal(t, "ES512", obj.Signatures[0].Header.Algorithm, "merged header did not contain expected alg value")
	assert.Equal(t, "ES512", obj.Signatures[0].Protected.Algorithm, "protected header did not contain expected alg value")
	assert.Equal(t, "", obj.Signatures[0].Unprotected.Algorithm, "unprotected header contained an alg value")
	assert.Equal(t, "test", obj.Signatures[0].Unprotected.ExtraHeaders["custom"], "unprotected header did not contain custom header value")
}

func TestErrorMissingPayloadJWS(t *testing.T) {
	_, err := (&rawJSONWebSignature{}).sanitized([]SignatureAlgorithm{RS256})
	assert.Error(t, err, "was able to parse message with missing payload")
	assert.Contains(t, err.Error(), "missing payload", "unexpected error message, should contain 'missing payload': %s", err)
}

func TestErrorUnexpectedSignatureAlgorithmInProtected(t *testing.T) {
	// protected: {"alg":"HS256", "jwk":{"kty":"oct", "k":"MTEx"}}
	msg := `{"payload":"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ","protected":"eyJhbGciOiJIUzI1NiIsICJqd2siOnsia3R5Ijoib2N0IiwgImsiOiJNVEV4In19","signature":"lvo41ZZsuHwQvSh0uJtEXRR3vmuBJ7in6qMoD7p9jyo"}`

	_, err := ParseSigned(msg, []SignatureAlgorithm{ES256})
	require.Error(t, err, "was able to parse message with unexpected signature algorithm")
	var errUnexpectedSigAlg *ErrUnexpectedSignatureAlgorithm
	require.True(t, errors.As(err, &errUnexpectedSigAlg), "unexpected error type, should be UnsupportedAlgorithmError")
	require.Equal(t, HS256, errUnexpectedSigAlg.Got)
	require.Len(t, errUnexpectedSigAlg.expected, 1)
	require.Equal(t, ES256, errUnexpectedSigAlg.expected[0])
}

func TestErrorUnexpectedSignatureAlgorithmInSignatures(t *testing.T) {
	// protected: {"alg":"HS256", "jwk":{"kty":"oct", "k":"MTEx"}}
	msg := `{
		"payload":"TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ",
		"signatures":[
			{
				"protected":"eyJhbGciOiJIUzI1NiIsICJqd2siOnsia3R5Ijoib2N0IiwgImsiOiJNVEV4In19",
				"signature":"lvo41ZZsuHwQvSh0uJtEXRR3vmuBJ7in6qMoD7p9jyo"
			}
		]
	}`

	_, err := ParseSigned(msg, []SignatureAlgorithm{ES256})
	require.Error(t, err, "was able to parse message with unexpected signature algorithm")
	var errUnexpectedSigAlg *ErrUnexpectedSignatureAlgorithm
	require.True(t, errors.As(err, &errUnexpectedSigAlg), "unexpected error type, should be UnsupportedAlgorithmError")
	require.Equal(t, HS256, errUnexpectedSigAlg.Got)
	require.Len(t, errUnexpectedSigAlg.expected, 1)
	require.Equal(t, ES256, errUnexpectedSigAlg.expected[0])
}

// Test that a null value in the header doesn't panic
func TestNullHeaderValue(t *testing.T) {
	msg := `{
   "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
   "protected":"eyJhbGciOiJFUzI1NiIsIm5vbmNlIjpudWxsfQ",
   "header":
    {"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"},
   "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
  }`

	defer func() {
		if r := recover(); r != nil {
			assert.Failf(t, "unexpected result", "ParseSigned panic'd when parsing a message with a null protected header value")
		}
	}()
	_, err := ParseSigned(msg, []SignatureAlgorithm{ES256})
	require.NoError(t, err)
}

// Test for bug:
// https://github.com/go-jose/go-jose/issues/157
func TestEmbedJWKBug(t *testing.T) {
	signerKey := SigningKey{
		Key: &JSONWebKey{
			Key:   rsaTestKey,
			KeyID: "rsa-test-key",
		},
		Algorithm: RS256,
	}

	signer, err := NewSigner(signerKey, &SignerOptions{EmbedJWK: true})
	require.NoError(t, err)

	signerNoEmbed, err := NewSigner(signerKey, &SignerOptions{EmbedJWK: false})
	require.NoError(t, err)

	jws, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
	require.NoError(t, err)

	jwsNoEmbed, err := signerNoEmbed.Sign([]byte("Lorem ipsum dolor sit amet"))
	require.NoError(t, err)

	// This used to panic with:
	// json: error calling MarshalJSON for type *jose.JSONWebKey: go-jose/go-jose: unknown key type '%!s(<nil>)'
	output := jws.FullSerialize()
	outputNoEmbed := jwsNoEmbed.FullSerialize()

	// Expected output with embed set to true is a JWS with the public JWK embedded, with kid header empty.
	// Expected output with embed set to false is that we set the kid header for key identification instead.
	parsed, err := ParseSigned(output, []SignatureAlgorithm{RS256})
	require.NoError(t, err)

	parsedNoEmbed, err := ParseSigned(outputNoEmbed, []SignatureAlgorithm{RS256})
	require.NoError(t, err)

	assert.Equal(t, "", parsed.Signatures[0].Header.KeyID, "expected kid field in protected header to be empty")
	assert.Equal(t, "rsa-test-key", parsed.Signatures[0].Header.JSONWebKey.KeyID, "expected rsa-test-key to be kid in embedded JWK in protected header")
	assert.Equal(t, "rsa-test-key", parsedNoEmbed.Signatures[0].Header.KeyID, "expected kid field in protected header to be rsa-test-key")
	assert.Nil(t, parsedNoEmbed.Signatures[0].Header.JSONWebKey, "expected no embedded JWK to be present")
}

func TestJWSWithCertificateChain(t *testing.T) {
	signerKey := SigningKey{
		Key:       rsaTestKey,
		Algorithm: RS256,
	}

	certs := []string{
		// CN=TrustedSigner, signed by IntermediateCA
		"MIIDOjCCAiKgAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOSW50ZXJtZWRpYXRlQ0EwHhcNMjAxMDA0MjMzNDA3WhcNNDAxMDA0MjMzNDA3WjAYMRYwFAYDVQQDDA1UcnVzdGVkU2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAswje1TAIK6aBvvVbuf3bq0emTEDXsTnovRv7HArauy0Lc72Gai8tuc1WVAmw8byxqaNHnHTfIT66UxPBcktr59A9KW2NqNXtNlhVgyIcYFEBFgmKjItmHG2BTw8HIvUnrcneRY9w/gE74f+7BPl0WUE2jsKkf8cIvZso5osGoBwVRN5YP0aWersaXVpA+hVUbMuwUnAvLdvuSvXDtL6SDdisHV9rhZH2jRAj6BzmC4mAD9BATeFFqC1Nt+bo1d7TUNk/FEbjyzs6g9QCUsTTL2RoPFvdQYjnYoIl4tVClUGipeEXb3e84k/ZEUDC04ENCONM/BsQEHBcR0eylViD7QIDAQABo4GMMIGJMB0GA1UdDgQWBBQ5GmxMDIgf21y8SDTSMy2/bZjcLjAfBgNVHSMEGDAWgBTZZOBbEfV70Ocm9RIM16yhAw4SyjAOBgNVHQ8BAf8EBAMCA7gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBgGA1UdEQQRMA+CDVRydXN0ZWRTaWduZXIwDQYJKoZIhvcNAQELBQADggEBAHS3KHVV/8H5eH2ZsDRsXyZkdqQlArlWCNK5I1xXW3jxnmAkrMu/Boin82foKLX7sNV33pdec8QMZMY3sTqr8OR+4haehYT9Dw6K4FEBtwRcuR08KducwnQO+kEeixkYtGpRX81hzLLdPHup9u+70WRsiSbgrYq9mV9bec+0uylbfh7ervNncIMTQvjZVkMnELrxe5l31UsZddHs2bzPbdlHuEhNmYxgzCXcFmpvv/WuuNiqVruQKzLYgR+F+eeE5UtmtE/gEBtPFHyLqQCoDcPqRY6B0VqNdcobPz4VOV8Fbf1HOzYEn7TdVglw6PTb5AXQ7/wnRss6SUofg6wzdzY=",
		// CN=IntermediateCA, signed by TrustedCA
		"MIIEDzCCAfegAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwFDESMBAGA1UEAwwJVHJ1c3RlZENBMB4XDTIwMTAwNDIzMDMzM1oXDTQwMTAwNDIzMDMzM1owGTEXMBUGA1UEAwwOSW50ZXJtZWRpYXRlQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDiKADoUoaNvD4yCLPySuPR1saLWHNRlt2nqbd7smwB1quNKnKwAKKnLyaBUHICFrQjCTA7IF7KUndVU0vutMFzn6hKuliZMYbwDQgx6x8u34m8Ar8cAg/AJPgT5Kk6Ds8soUaTzRG/GXVjGll0ArjRp97LmOW1Tc53R4YJji6eTThgb4Al6XDou2AeEMNYC46yqafwzOvHOnzSQwy8IwdcFjNKry15pvutIK3UhZscAmfbNEN5ou3miWcz3PuVGORxKAqlA4mYoJWE2AF52fgNTYcTFCDdiThaFSBzgqEgFoDzzROhf1B+/bSJ4gULK9YQxpXVmt8/tlvXjNygDj1LAgMBAAGjZjBkMB0GA1UdDgQWBBTZZOBbEfV70Ocm9RIM16yhAw4SyjAfBgNVHSMEGDAWgBTJ8bqL9u+G1ykEpl9uakSgZGq3JDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEADfEtLh3YDabrTsx+KmJ1f8ybwdltgI3gPiubd5RcYcoO3Pd33/INJDMkJYfLCrSDLI5Y94szOUhkP/rSwrUgJErnPSPUEW11GgA230d7vjc3bFJO/bPb2ZAwm/eC7dMMyyDH/2Wty7h7SOuXXJljZYIvuavJymZxsmkDAu7MtdntHVLr5bruEYvM9IKad9YZSchRP1Q3kIZuTmNvBgLGwrVw/UcOpczajULNNzPUNPDFs9Zo04tx/YF1R1fOGUhif13DMk+6JU7zUXZL3iqOSkxBRrlMQX6nKAQ68cMqO2UsrfXBqH5xm3O9+NxsfN3CkkTcyBcvVFMaMe0670lCh3DcFOMDt2YdlqS5tEsBn3TdOFKSjv2dVnT2eeXcq5IvuC4nkEXzZDROfQVrnraBhHOiyLAlfwhA1LHZGlJfNZaWRDdXHKV+pIMr2JyOv/hf9aaWzjwyy7FJwn3yrEwHGfBgx0vgKPj6l6N8qxQ6l1XMyANx4ExlpXfffx+CPWV9eeMi4Wh6V9641LesQnlOGgL5R03jQRjaicp3nvzsNElDEgPq0s9PE8s6weFKBz5ykrw/Gg4QWmw6MfwjOX5Fu1oJF9ABoCFD5umvKhpoJkcT8aYM0+E1xiEAx64uWq2b2GCGP4wMEZuqCcE72fiue295ovPkNsbEjTQk/ijWza0=",
	}

	testCases := []struct {
		// Cert chain to embed in message
		chain []string
		// Intermediates & root certificate to verify against
		intermediates []string
		root          string
		// Should this test case verify?
		success bool
	}{
		{certs, nil, trustedCA, true},
		{certs, []string{intermediateCA}, trustedCA, true},
		{certs[0:1], nil, intermediateCA, true},
		{certs[0:1], nil, trustedCA, false},
		{[]string{}, nil, trustedCA, false},
	}

	for i, testCase := range testCases {
		signer, err := NewSigner(signerKey, &SignerOptions{
			ExtraHeaders: map[HeaderKey]any{HeaderKey("x5c"): testCase.chain},
		})
		require.NoError(t, err)

		signed, err := signer.Sign([]byte("Lorem ipsum dolor sit amet"))
		require.NoError(t, err)

		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{RS256})
		require.NoError(t, err)

		opts := x509.VerifyOptions{
			DNSName: "TrustedSigner",
			Roots:   x509.NewCertPool(),
		}

		ok := opts.Roots.AppendCertsFromPEM([]byte(testCase.root))
		require.True(t, ok, "failed to parse trusted root certificate")

		if len(testCase.intermediates) > 0 {
			opts.Intermediates = x509.NewCertPool()
			for _, intermediate := range testCase.intermediates {
				ok := opts.Intermediates.AppendCertsFromPEM([]byte(intermediate))
				require.True(t, ok, "failed to parse trusted root certificate")
			}
		}

		chains, err := parsed.Signatures[0].Protected.Certificates(opts)
		if testCase.success && (len(chains) == 0 || err != nil) {
			require.Failf(t, "unexpected result", "failed to verify certificate chain for test case %d: %s", i, err)
		}
		if !testCase.success && (len(chains) != 0 && err == nil) {
			require.Failf(t, "unexpected result", "incorrectly verified certificate chain for test case %d (should fail)", i)
		}
	}
}

func TestDetachedCompactSerialization(t *testing.T) {
	msg := "eyJhbGciOiJSUzI1NiJ9.JC4wMg.W5tc_EUhxexcvLYEEOckyyvdb__M5DQIVpg6Nmk1XGM"
	exp := "eyJhbGciOiJSUzI1NiJ9..W5tc_EUhxexcvLYEEOckyyvdb__M5DQIVpg6Nmk1XGM"

	obj, err := ParseSigned(msg, []SignatureAlgorithm{RS256})
	require.NoError(t, err)

	ser, err := obj.DetachedCompactSerialize()
	require.NoError(t, err)

	require.Equal(t, exp, ser, "got '%s', expected '%s'", ser, exp)

	obj, err = ParseDetached(ser, []byte("$.02"), []SignatureAlgorithm{RS256})
	require.NoError(t, err)

	ser, err = obj.CompactSerialize()
	require.NoError(t, err)

	require.Equal(t, msg, ser, "got '%s', expected '%s'", ser, msg)
}

func TestJWSComputeAuthDataBase64(t *testing.T) {
	jws := JSONWebSignature{}

	_, err := jws.computeAuthData([]byte{0x01}, &Signature{
		original: &rawSignatureInfo{
			Protected: newBuffer([]byte("{!invalid-json}")),
		},
	})
	// Invalid header, should return error
	assert.Error(t, err, "expected error when computing auth data for invalid signature")

	payload := []byte{0x01}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	b64TrueHeader := newBuffer([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM","b64":true}`))
	b64FalseHeader := newBuffer([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM","b64":false}`))

	data, err := jws.computeAuthData(payload, &Signature{
		original: &rawSignatureInfo{
			Protected: b64TrueHeader,
		},
	})
	assert.NoError(t, err, "computing auth data for \"b64\": true")

	// Payload should be b64 encoded
	assert.Len(t, data, len(b64TrueHeader.base64())+len(encodedPayload)+1)

	data, err = jws.computeAuthData(payload, &Signature{
		original: &rawSignatureInfo{
			Protected: b64FalseHeader,
		},
	})
	assert.NoError(t, err, "computing auth data for \"b64\": false")
	// Payload should *not* be b64 encoded
	assert.Len(t, data, len(b64FalseHeader.base64())+len(payload)+1)
}

func TestInvalidHMACKeySize(t *testing.T) {
	s, err := NewSigner(SigningKey{
		Key:       make([]byte, 31),
		Algorithm: HS256,
	}, nil)
	assert.NoError(t, err)
	_, err = s.Sign([]byte("Lorem ipsum dolor sit amet"))
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	s, err = NewSigner(SigningKey{
		Key:       make([]byte, 47),
		Algorithm: HS384,
	}, nil)
	assert.NoError(t, err)
	_, err = s.Sign([]byte("Lorem ipsum dolor sit amet"))
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	s, err = NewSigner(SigningKey{
		Key:       make([]byte, 63),
		Algorithm: HS512,
	}, nil)
	assert.NoError(t, err)
	_, err = s.Sign([]byte("Lorem ipsum dolor sit amet"))
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}

// RFC 7515 Section 5.2 step 3.
func TestParseSignedJSONRejectsAProtectedHeaderWhichIsNotAnObject(t *testing.T) {
	for _, protected := range []string{"", "null", " null ", "[]", `"alg"`, "1", "true"} {
		t.Run(protected, func(t *testing.T) {
			b64 := base64.RawURLEncoding.EncodeToString([]byte(protected))

			inputs := map[string]string{
				"Flattened": `{"protected":"` + b64 + `","header":{"alg":"HS256"},"payload":"cGF5bG9hZA","signature":"AAAA"}`,
				"General":   `{"payload":"cGF5bG9hZA","signatures":[{"protected":"` + b64 + `","header":{"alg":"HS256"},"signature":"AAAA"}]}`,
			}

			for name, input := range inputs {
				_, err := ParseSignedJSON(input, []SignatureAlgorithm{HS256})
				assert.Error(t, err, "%s: ParseSignedJSON accepted a protected header of %s", name, protected)
			}
		})
	}

	b64 := base64.RawURLEncoding.EncodeToString([]byte(` {"alg":"HS256"} `))

	_, err := ParseSignedJSON(`{"protected":"`+b64+`","payload":"cGF5bG9hZA","signature":"AAAA"}`, []SignatureAlgorithm{HS256})
	assert.NoError(t, err, "ParseSignedJSON rejected a protected header object surrounded by whitespace")
}

// RFC 7493 Section 2.1.
func TestJWSHeaderRejectsInvalidUnicode(t *testing.T) {
	for _, header := range []string{`{"alg":"HS256","kid":"\ud800"}`, "{\"alg\":\"HS256\",\"kid\":\"a\xffb\"}"} {
		input := base64.RawURLEncoding.EncodeToString([]byte(header)) + ".cGF5bG9hZA.AAAA"

		_, err := ParseSignedCompact(input, []SignatureAlgorithm{HS256})
		assert.Error(t, err, "ParseSignedCompact accepted the header %q", header)
	}

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: bytes.Repeat([]byte{1}, 32)}, (&SignerOptions{}).WithHeader("x", "a\xffb"))
	require.NoError(t, err, "NewSigner")

	_, err = signer.Sign([]byte("payload"))
	assert.Error(t, err, "Sign accepted a header value which is not valid UTF-8")
}

// RFC 7797 Section 3.
func TestParseSignedJSONRejectsUnprotectedB64(t *testing.T) {
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))

	for _, b64 := range []string{"false", "true"} {
		inputs := map[string]string{
			"Flattened": `{"protected":"` + protected + `","header":{"b64":` + b64 + `},"payload":"cGF5bG9hZA","signature":"AAAA"}`,
			"General":   `{"payload":"cGF5bG9hZA","signatures":[{"protected":"` + protected + `","header":{"b64":` + b64 + `},"signature":"AAAA"}]}`,
		}

		for name, input := range inputs {
			_, err := ParseSignedJSON(input, []SignatureAlgorithm{HS256})
			assert.Error(t, err, "%s: ParseSignedJSON accepted an unprotected b64 of %s", name, b64)
		}
	}
}

func BenchmarkParseSignedCompat(b *testing.B) {
	raw := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0In0.OFD0iVfPczqWBA_TRi1jGB5PF699eekcHt4D6qNoimc`

	for range b.N {
		if _, err := ParseSignedCompact(raw, []SignatureAlgorithm{HS256}); err != nil {
			panic(err)
		}
	}
}

// RFC 7515 Section 7.1 defines the compact serialization as three base64url segments separated by periods, which
// leaves no room for whitespace. Silently removing it gives one logical token unlimited textual representations, each
// of which verifies, so anything keyed on the token text disagrees with what is accepted. See go-jose/go-jose#244.
func TestParseSignedDoesNotStripCompactWhitespace(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, nil)
	require.NoError(t, err, "NewSigner")

	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err, "Sign")

	compact, err := obj.CompactSerialize()
	require.NoError(t, err, "CompactSerialize")

	detached, err := obj.DetachedCompactSerialize()
	require.NoError(t, err, "DetachedCompactSerialize")

	testCases := []struct {
		name     string
		have     string
		detached string
	}{
		{
			"ShouldRejectSpacesAroundDelimiter",
			strings.Replace(compact, ".", " . ", 1),
			strings.Replace(detached, ".", " . ", 1),
		},
		{
			"ShouldRejectNewlineAfterDelimiter",
			strings.Replace(compact, ".", ".\n", 1),
			strings.Replace(detached, ".", ".\n", 1),
		},
		{
			"ShouldRejectWhitespaceWithinSegment",
			compact[:10] + " " + compact[10:],
			detached[:10] + " " + detached[10:],
		},
		// Go's base64 decoder silently ignores carriage returns and newlines, so a segment containing either decodes
		// as though it were absent unless the serialization is rejected before it is decoded.
		{
			"ShouldRejectNewlineWithinSegment",
			compact[:10] + "\n" + compact[10:],
			detached[:10] + "\n" + detached[10:],
		},
		{
			"ShouldRejectCarriageReturnWithinSegment",
			compact[:10] + "\r" + compact[10:],
			detached[:10] + "\r" + detached[10:],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseSigned(tc.have, []SignatureAlgorithm{HS256})
			assert.Error(t, err, "ParseSigned accepted compact serialization with internal whitespace")

			_, err = ParseSignedCompact(tc.have, []SignatureAlgorithm{HS256})
			assert.Error(t, err, "ParseSignedCompact accepted compact serialization with internal whitespace")

			_, err = ParseDetached(tc.detached, []byte("payload"), []SignatureAlgorithm{HS256})
			assert.Error(t, err, "ParseDetached accepted compact serialization with internal whitespace")
		})
	}
}

// Leading and trailing whitespace, such as a trailing newline from a file or an environment variable, is common and
// carries none of the risk of stripping whitespace from within the token, so it must still be tolerated.
func TestParseSignedTrimsOuterWhitespace(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: key}, nil)
	require.NoError(t, err, "NewSigner")

	obj, err := signer.Sign([]byte("payload"))
	require.NoError(t, err, "Sign")

	compact, err := obj.CompactSerialize()
	require.NoError(t, err, "CompactSerialize")

	padded := "\n  " + compact + "  \n"

	parsed, err := ParseSigned(padded, []SignatureAlgorithm{HS256})
	require.NoError(t, err, "ParseSigned rejected compact serialization with outer whitespace")

	payload, err := parsed.Verify(key)
	require.NoError(t, err, "Verify")

	assert.Equal(t, "payload", string(payload), "payload = %q, want %q", payload, "payload")

	detached, err := obj.DetachedCompactSerialize()
	require.NoError(t, err, "DetachedCompactSerialize")

	_, err = ParseDetached("\n  "+detached+"  \n", []byte("payload"), []SignatureAlgorithm{HS256})
	assert.NoError(t, err, "ParseDetached rejected compact serialization with outer whitespace")
}

// An embedded OKP JWK whose "x" resolves to the Ed25519 identity point accepts a signature which anyone can construct
// without a private key, because [s]B == R + [k]A holds for s of zero, R of the identity point and A the identity
// point, whatever the payload. Such a JWK must never survive parsing. See go-jose/go-jose#249.
func TestEmbeddedEd25519IdentityPointCannotForgeSignature(t *testing.T) {
	testCases := []struct {
		name string
		x    []byte
	}{
		{"ShouldRejectTruncatedX", []byte{0x01}},
		{
			"ShouldRejectIdentityPoint",
			fromHexBytes(`0100000000000000000000000000000000000000000000000000000000000000`),
		},
		{
			"ShouldRejectIdentityPointSignBitAlias",
			fromHexBytes(`0100000000000000000000000000000000000000000000000000000000000080`),
		},
	}

	// R is the identity point and s is zero.
	forged := make([]byte, 64)
	forged[0] = 0x01

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			protected := []byte(`{"alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":"` +
				base64.RawURLEncoding.EncodeToString(tc.x) + `"}}`)

			msg := strings.Join([]string{
				base64.RawURLEncoding.EncodeToString(protected),
				base64.RawURLEncoding.EncodeToString([]byte("forged payload")),
				base64.RawURLEncoding.EncodeToString(forged),
			}, ".")

			object, err := ParseSigned(msg, []SignatureAlgorithm{EdDSA})
			if err != nil {
				return
			}

			payload, err := object.Verify(object.Signatures[0].Header.JSONWebKey)
			require.Error(t, err, "forged signature was accepted, returning payload %q", payload)
		})
	}
}

// The per-signature unprotected header was assigned after the merged and
// unprotected headers had already been derived from it, so in the general JSON
// serialization Header lost the unprotected values and Unprotected stayed
// empty. That is where "kid" normally lives for that serialization, so JWKS
// backed verification could not find a key.
func TestParseSignedJSONSurfacesPerSignatureHeader(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(protected + "." + payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	serialized := fmt.Sprintf(
		`{"payload":%q,"signatures":[{"protected":%q,"header":{"kid":"k1"},"signature":%q}]}`,
		payload, protected, signature)

	obj, err := ParseSignedJSON(serialized, []SignatureAlgorithm{HS256})
	require.NoError(t, err, "ParseSignedJSON")

	got := obj.Signatures[0].Header.KeyID
	assert.Equal(t, "k1", got, "Header.KeyID = %q, want %q", got, "k1")

	got = obj.Signatures[0].Unprotected.KeyID
	assert.Equal(t, "k1", got, "Unprotected.KeyID = %q, want %q", got, "k1")

	// The protected header must not pick up unprotected values.
	got = obj.Signatures[0].Protected.KeyID
	assert.Equal(t, "", got, "Protected.KeyID = %q, want empty", got)

	_, err = obj.Verify(key)
	assert.NoError(t, err, "Verify")
}

// RFC 7515 Section 5.2 step 4 requires a validator to reject a JOSE Header
// carrying the same parameter name twice, including across the protected and
// unprotected objects. Merging resolved the collision by precedence instead, so
// an attacker could attach an unprotected "kid" naming a different key to a
// legitimately signed message and have it reported as the signer's identity.
func TestParseSignedRejectsDuplicateHeaderParameters(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"real"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(protected + "." + payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	testCases := []struct {
		name       string
		serialized string
		wantErr    bool
	}{
		{
			"FlattenedDuplicateKeyID",
			fmt.Sprintf(`{"payload":%q,"protected":%q,"header":{"kid":"attacker"},"signature":%q}`, payload, protected, signature),
			true,
		},
		{
			"FlattenedDuplicateAlgorithm",
			fmt.Sprintf(`{"payload":%q,"protected":%q,"header":{"alg":"none"},"signature":%q}`, payload, protected, signature),
			true,
		},
		{
			"GeneralDuplicateKeyID",
			fmt.Sprintf(`{"payload":%q,"signatures":[{"protected":%q,"header":{"kid":"attacker"},"signature":%q}]}`, payload, protected, signature),
			true,
		},
		{
			"DisjointHeadersAreFine",
			fmt.Sprintf(`{"payload":%q,"protected":%q,"header":{"cty":"JWT"},"signature":%q}`, payload, protected, signature),
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			obj, err := ParseSignedJSON(tc.serialized, []SignatureAlgorithm{HS256})

			if tc.wantErr {
				require.ErrorIs(t, err, ErrDuplicateHeaderParameter, "got %v, want %v", err, ErrDuplicateHeaderParameter)

				return
			}

			require.NoError(t, err, "ParseSignedJSON")

			_, err = obj.Verify(key)
			assert.NoError(t, err, "Verify")
		})
	}
}

// RFC 4648 Section 3.5 requires an encoder to zero the unused bits of the final
// quantum, and permits a decoder to reject them set. Go's decoder does not, so
// several distinct strings decoded to the same octets and every one verified.
// A token had no single spelling, which defeats any cache keyed on it: a replay
// or revocation check on the token string could be sidestepped by re-encoding.
func TestParseRejectsNonCanonicalBase64(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")

	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(protected + "." + payload))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	canonical := protected + "." + payload + "." + signature

	obj, err := ParseSignedCompact(canonical, []SignatureAlgorithm{HS256})
	require.NoError(t, err, "the canonical token must still parse")

	_, err = obj.Verify(key)
	require.NoError(t, err, "the canonical token must still verify")

	// Flip the unused trailing bits of a segment's final character. The octets it
	// decodes to are unchanged, so without the check the variant verifies too.
	variants := map[string]string{
		"payload":   protected + "." + flipUnusedBits(t, payload) + "." + signature,
		"signature": protected + "." + payload + "." + flipUnusedBits(t, signature),
	}

	for name, variant := range variants {
		require.NotEqual(t, canonical, variant, "%s: the variant is identical to the canonical form", name)

		_, err = ParseSignedCompact(variant, []SignatureAlgorithm{HS256})
		assert.Error(t, err, "%s: a non-canonical encoding was accepted", name)
	}
}

// flipUnusedBits returns s with the unused bits of its final quantum set, which
// leaves the decoded octets unchanged.
func flipUnusedBits(t *testing.T, s string) string {
	t.Helper()

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

	unused := map[int]int{2: 4, 3: 2}[len(s)%4]
	require.NotEqual(t, 0, unused, "a %d character segment has no unused bits to flip", len(s))

	index := strings.IndexByte(alphabet, s[len(s)-1])
	if index < 0 {
		require.Failf(t, "unexpected result", "segment ends in %q, which is not base64url", s[len(s)-1])
	}

	// Set the low bits that the encoding does not use.
	return s[:len(s)-1] + string(alphabet[index|(1<<unused-1)])
}

// RFC 7797 Section 6 requires "b64" to be listed in "crit" whenever it is used, so that an implementation which
// does not implement "b64" rejects the JWS instead of misreading it. Without that requirement one signed blob is
// read as raw octets here and as base64url decoded octets by a strict verifier, under a signature that is valid
// for both: the confusion RFC 7797 Section 8 describes.
func TestParseRejectsB64WithoutCrit(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")
	payload := []byte("NDA1")

	testCases := []struct {
		name    string
		header  string
		b64     bool
		wantErr bool
	}{
		{"UnencodedWithoutCritical", `{"alg":"HS256","b64":false}`, false, true},
		{"UnencodedCriticalOmitsB64", `{"alg":"HS256","b64":false,"x-custom":1,"crit":["x-custom"]}`, false, true},
		{"EncodedWithoutCritical", `{"alg":"HS256","b64":true}`, true, true},
		{"UnencodedCriticalListsB64", `{"alg":"HS256","b64":false,"crit":["b64"]}`, false, false},
		{"ParameterAbsent", `{"alg":"HS256"}`, true, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for name, parse := range signedJWSForms(t, key, tc.header, tc.b64, payload) {
				obj, err := parse()

				if tc.wantErr {
					assert.ErrorIs(t, err, ErrB64NotCritical, "%s: got %v, want %v", name, err, ErrB64NotCritical)

					continue
				}

				if !assert.NoError(t, err, "%s: parse", name) {
					continue
				}

				// The message is well formed, so it must still verify against the payload it carries.
				if name == "detached" {
					err = obj.DetachedVerify(payload, key)
					assert.NoError(t, err, "%s: DetachedVerify", name)

					continue
				}

				output, err := obj.Verify(key)
				if !assert.NoError(t, err, "%s: Verify", name) {
					continue
				}

				assert.Equal(t, payload, output, "%s: payload = %q, want %q", name, output, payload)
			}
		})
	}
}

// RFC 7515 Section 4.1.11 constrains "crit" itself: it must not be empty, must not repeat a name, and must not
// name a parameter which does not occur in the header. All three were accepted, which matters more now that
// "crit" governs whether "b64" is honoured: an empty list and a list naming an absent parameter are both
// meaningless instructions to the recipient, and a duplicate hides how many parameters were really marked.
func TestParseRejectsMalformedCritical(t *testing.T) {
	key := []byte("0123456789ABCDEF0123456789ABCDEF")
	payload := []byte("NDA1")

	testCases := []struct {
		name    string
		header  string
		b64     bool
		wantErr bool
	}{
		{"EmptyList", `{"alg":"HS256","crit":[]}`, true, true},
		{"DuplicateEntry", `{"alg":"HS256","b64":false,"crit":["b64","b64"]}`, false, true},
		{"NamesAbsentParameter", `{"alg":"HS256","crit":["b64"]}`, true, true},
		{"NamesPresentParameter", `{"alg":"HS256","b64":false,"crit":["b64"]}`, false, false},
		{"ParameterAbsent", `{"alg":"HS256"}`, true, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for name, parse := range signedJWSForms(t, key, tc.header, tc.b64, payload) {
				obj, err := parse()

				if tc.wantErr {
					assert.ErrorIs(t, err, ErrInvalidCriticalHeader, "%s: got %v, want %v", name, err, ErrInvalidCriticalHeader)

					continue
				}

				if !assert.NoError(t, err, "%s: parse", name) {
					continue
				}

				err = obj.DetachedVerify(payload, key)
				assert.NoError(t, err, "%s: DetachedVerify", name)
			}
		})
	}

	// A name the header does carry but which this package reserves stays the allow-list's business, and is still
	// reported as unsupported rather than as malformed.
	for name, parse := range signedJWSForms(t, key, `{"alg":"HS256","crit":["alg"]}`, true, payload) {
		obj, err := parse()
		if !assert.NoError(t, err, "%s: parse", name) {
			continue
		}

		err = obj.DetachedVerify(payload, key)
		assert.ErrorIs(t, err, ErrUnsupportedCriticalHeader, "%s: DetachedVerify: got %v, want %v", name, err, ErrUnsupportedCriticalHeader)
	}
}

// signedJWSForms returns the compact, detached and JSON serializations of a JWS over payload with the given
// protected header, each as a parse to run. The signature is genuine, so a message these reject is one that
// would otherwise have verified.
func signedJWSForms(t *testing.T, key []byte, header string, b64 bool, payload []byte) map[string]func() (*JSONWebSignature, error) {
	t.Helper()

	protected := base64.RawURLEncoding.EncodeToString([]byte(header))

	wire := string(payload)
	if b64 {
		wire = base64.RawURLEncoding.EncodeToString(payload)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(protected + "." + wire))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return map[string]func() (*JSONWebSignature, error){
		"compact": func() (*JSONWebSignature, error) {
			return ParseSignedCompact(protected+"."+wire+"."+signature, []SignatureAlgorithm{HS256})
		},
		"detached": func() (*JSONWebSignature, error) {
			return ParseDetached(protected+".."+signature, payload, []SignatureAlgorithm{HS256})
		},
		"json": func() (*JSONWebSignature, error) {
			return ParseSignedJSON(
				fmt.Sprintf(`{"payload":%q,"protected":%q,"signature":%q}`, wire, protected, signature),
				[]SignatureAlgorithm{HS256},
			)
		},
	}
}

// RFC 7515 Section 5.2 verifies the signature over the protected header exactly as it was encoded. A parsed JWS was
// previously re-serialized with its protected header re-marshaled, which reorders its members, so a token from any
// issuer that did not happen to emit them in this package's order no longer verified after being passed along.
func TestSerializeParsedSignatureKeepsProtectedHeader(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString

	keys := [][]byte{
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("fedcba9876543210fedcba9876543210"),
	}

	protected := []string{`{"typ":"JWT","alg":"HS256"}`, `{"kid":"2",  "alg":"HS256"}`}
	payload := b64([]byte(`{"a":1}`))

	sign := func(i int) (string, string) {
		mac := hmac.New(sha256.New, keys[i])
		mac.Write([]byte(b64([]byte(protected[i])) + "." + payload))

		return b64([]byte(protected[i])), b64(mac.Sum(nil))
	}

	reparse := func(t *testing.T, serialized string) *JSONWebSignature {
		obj, err := ParseSigned(serialized, []SignatureAlgorithm{HS256})
		require.NoError(t, err, "failed to reparse %s", serialized)

		return obj
	}

	t.Run("ShouldKeepCompactSerialization", func(t *testing.T) {
		header, signature := sign(0)
		token := header + "." + payload + "." + signature

		serialized, err := reparse(t, token).CompactSerialize()
		assert.NoError(t, err)
		assert.Equal(t, token, serialized)

		_, err = reparse(t, serialized).Verify(keys[0])
		assert.NoError(t, err)
	})

	t.Run("ShouldKeepFlattenedSerialization", func(t *testing.T) {
		header, signature := sign(0)

		serialized := reparse(t, header+"."+payload+"."+signature).FullSerialize()

		_, err := reparse(t, serialized).Verify(keys[0])
		assert.NoError(t, err)
	})

	t.Run("ShouldKeepGeneralSerialization", func(t *testing.T) {
		header0, signature0 := sign(0)
		header1, signature1 := sign(1)

		token := `{"payload":"` + payload + `","signatures":[` +
			`{"protected":"` + header0 + `","signature":"` + signature0 + `"},` +
			`{"protected":"` + header1 + `","signature":"` + signature1 + `"}]}`

		serialized := reparse(t, token).FullSerialize()

		for i, key := range keys {
			index, _, _, err := reparse(t, serialized).VerifyMulti(key)
			assert.NoError(t, err)
			assert.Equal(t, i, index)
		}
	})
}

// RFC 7515 Section 7.2.2 defines the flattened members "protected", "header" and "signature" only for a JWS without a
// "signatures" array. A general serialization carrying them as well was previously accepted with them silently
// dropped, so a parser taking the other reading saw a different algorithm, key and signature.
func TestParseSignedRejectsMixedJSONSerialization(t *testing.T) {
	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		{Algorithm: HS256, Key: []byte("fedcba9876543210fedcba9876543210")},
	}, nil)
	assert.NoError(t, err)

	obj, err := signer.Sign([]byte("payload"))
	assert.NoError(t, err)

	general := obj.FullSerialize()

	parse := func(serialized string) error {
		_, err := ParseSigned(serialized, []SignatureAlgorithm{HS256})

		return err
	}

	assert.NoError(t, parse(general))

	b64 := base64.RawURLEncoding.EncodeToString

	testCases := []struct {
		name   string
		member string
	}{
		{"ShouldRejectProtected", `"protected":"` + b64([]byte(`{"alg":"none"}`)) + `"`},
		{"ShouldRejectHeader", `"header":{"kid":"other"}`},
		{"ShouldRejectSignature", `"signature":"` + b64(make([]byte, 32)) + `"`},
		{"ShouldRejectNullProtected", `"protected":null`},
		{"ShouldRejectNullHeader", `"header":null`},
		{"ShouldRejectNullSignature", `"signature":null`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := parse("{" + tc.member + "," + general[1:])
			require.Error(t, err, "parsed a general serialization carrying a flattened member")
		})
	}

	t.Run("ShouldRejectNullSignatures", func(t *testing.T) {
		flattened, err := NewSigner(SigningKey{Algorithm: HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
		assert.NoError(t, err)

		obj, err := flattened.Sign([]byte("payload"))
		assert.NoError(t, err)

		serialized := obj.FullSerialize()

		assert.NoError(t, parse(serialized))
		assert.Error(t, parse(`{"signatures":null,`+serialized[1:]))
	})
}

func TestEmbeddedPrivateJWKRejected(t *testing.T) {
	privateJWK, err := fromRsaPrivateKey(rsaTestKey)
	require.NoError(t, err)
	publicJWK, err := fromRsaPublicKey(&rsaTestKey.PublicKey)
	require.NoError(t, err)
	strayJWK, err := fromRsaPublicKey(&rsaTestKey.PublicKey)
	require.NoError(t, err)
	strayJWK.P, strayJWK.Q = privateJWK.P, privateJWK.Q

	testCases := []struct {
		name        string
		jwk         *rawJSONWebKey
		unprotected bool // place the jwk in the unprotected header instead
		wantErr     bool
	}{
		{name: "public key", jwk: publicJWK},
		{name: "private key", jwk: privateJWK, wantErr: true},
		{name: "private key in unprotected header", jwk: privateJWK, unprotected: true, wantErr: true},
		{name: "symmetric key", jwk: &rawJSONWebKey{Kty: "oct", K: newBuffer([]byte("111"))}, wantErr: true},
		{name: "public key with stray private members", jwk: strayJWK, wantErr: true},
		{name: "akp private key", jwk: &rawJSONWebKey{Kty: "AKP", Alg: "ML-DSA-44", Pub: newBuffer([]byte("pub")), Priv: newBuffer([]byte("seed"))}, wantErr: true},
	}

	payload := wirePayload([]byte("Lorem ipsum dolor sit amet"), true)
	signature := newBuffer([]byte("not a real signature"))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			marshal := func(v any) []byte {
				t.Helper()
				b, err := json.Marshal(v)
				require.NoError(t, err)
				return b
			}

			alg := json.RawMessage(`"RS256"`)
			jwk := json.RawMessage(marshal(tc.jwk))
			protected := rawHeader{headerAlgorithm: &alg}
			var unprotected *rawHeader
			if tc.unprotected {
				unprotected = &rawHeader{headerJWK: &jwk}
			} else {
				protected[headerJWK] = &jwk
			}
			encProtected := newBuffer(marshal(protected))

			messages := map[string]string{
				"flattened": string(marshal(rawJSONWebSignature{
					Payload:   payload,
					Protected: encProtected,
					Header:    unprotected,
					Signature: signature,
				})),
				"general": string(marshal(rawJSONWebSignature{
					Payload: payload,
					Signatures: []rawSignatureInfo{{
						Protected: encProtected,
						Header:    unprotected,
						Signature: signature,
					}},
				})),
			}
			if !tc.unprotected {
				messages["compact"] = encProtected.base64() + "." + base64.RawURLEncoding.EncodeToString([]byte("Lorem ipsum dolor sit amet")) + "." + signature.base64()
			}

			for name, msg := range messages {
				_, err := ParseSigned(msg, []SignatureAlgorithm{RS256})
				if tc.wantErr {
					assert.ErrorContains(t, err, "JWK contains private parameters", "%s: expected private parameters error, got", name)
				} else if err != nil {
					assert.Failf(t, "unexpected result", "%s: unexpected error: %v", name, err)
				}
			}
		})
	}
}

func TestGeneralSerializationUnprotectedHeader(t *testing.T) {
	// The unprotected header of each signature must be reflected in the parsed
	// Header and Unprotected fields for both serializations.
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte("Lorem ipsum dolor sit amet"))
	signature := base64.RawURLEncoding.EncodeToString([]byte("not a real signature"))
	unprotected := `"header":{"kid":"from-unprotected"}`

	messages := map[string]string{
		"flattened": `{"payload":"` + payload + `","protected":"` + protected + `",` + unprotected + `,"signature":"` + signature + `"}`,
		"general":   `{"payload":"` + payload + `","signatures":[{"protected":"` + protected + `",` + unprotected + `,"signature":"` + signature + `"}]}`,
	}
	for name, msg := range messages {
		t.Run(name, func(t *testing.T) {
			obj, err := ParseSigned(msg, []SignatureAlgorithm{RS256})
			require.NoError(t, err)
			sig := obj.Signatures[0]
			assert.Equal(t, "from-unprotected", sig.Header.KeyID, "Header.KeyID = %q, want %q", sig.Header.KeyID, "from-unprotected")
			assert.Equal(t, "from-unprotected", sig.Unprotected.KeyID, "Unprotected.KeyID = %q, want %q", sig.Unprotected.KeyID, "from-unprotected")
		})
	}
}

func TestUnexpectedAlgorithmCheckedBeforeHeaders(t *testing.T) {
	// A message with an unexpected algorithm must be rejected as such, before
	// the rest of the header, including any embedded key, is parsed.
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","jwk":"not a key"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte("Lorem ipsum dolor sit amet"))
	signature := base64.RawURLEncoding.EncodeToString([]byte("not a real signature"))

	messages := map[string]string{
		"compact":   protected + "." + payload + "." + signature,
		"flattened": `{"payload":"` + payload + `","protected":"` + protected + `","signature":"` + signature + `"}`,
		"general":   `{"payload":"` + payload + `","signatures":[{"protected":"` + protected + `","signature":"` + signature + `"}]}`,
	}
	for name, msg := range messages {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSigned(msg, []SignatureAlgorithm{RS256})
			var errUnexpectedSigAlg *ErrUnexpectedSignatureAlgorithm
			require.True(t, errors.As(err, &errUnexpectedSigAlg), "expected ErrUnexpectedSignatureAlgorithm, got %v", err)
		})
	}
}

func TestFullSerializeNoSignatures(t *testing.T) {
	out := (JSONWebSignature{}).FullSerialize()
	assert.Equal(t, "", out, "expected empty string, got %q", out)
}

func TestParseSignedMaxSignatures(t *testing.T) {
	defer func(old int) { MaxSignatures = old }(MaxSignatures)

	// makeJWS makes a JWS with n signatures.
	makeJWS := func(n int) string {
		sigs := strings.TrimSuffix(strings.Repeat(`{"protected":"eyJhbGciOiJSUzI1NiJ9","signature":"AA"},`, n), ",")
		return `{"payload":"AA","signatures":[` + sigs + `]}`
	}

	testCases := []struct {
		name       string
		signatures int
		limit      int // override for MaxSignatures, 0 for default
		wantErr    bool
	}{
		{name: "at limit", signatures: 32},
		{name: "over limit", signatures: 33, wantErr: true},
		{name: "far over limit", signatures: 10000, wantErr: true},
		{name: "raised limit", signatures: 33, limit: 33},
		{name: "lowered limit", signatures: 2, limit: 1, wantErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			MaxSignatures = 32
			if tc.limit != 0 {
				MaxSignatures = tc.limit
			}
			obj, err := ParseSigned(makeJWS(tc.signatures), []SignatureAlgorithm{RS256})
			if tc.wantErr {
				require.ErrorContains(t, err, "too many signatures", "expected too many signatures error")
				return
			}
			require.NoError(t, err, "unexpected error")
			assert.Len(t, obj.Signatures, tc.signatures)
		})
	}
}

func TestParseSignedMaxSignaturesCountsSingleSignature(t *testing.T) {
	defer func(old int) { MaxSignatures = old }(MaxSignatures)

	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	flattened := `{"payload":"AA","protected":"` + protected + `","signature":"AA"}`
	compact := protected + ".AA.AA"

	for name, parse := range map[string]func() (*JSONWebSignature, error){
		"flattened": func() (*JSONWebSignature, error) { return ParseSignedJSON(flattened, []SignatureAlgorithm{RS256}) },
		"compact":   func() (*JSONWebSignature, error) { return ParseSignedCompact(compact, []SignatureAlgorithm{RS256}) },
	} {
		t.Run(name, func(t *testing.T) {
			MaxSignatures = 0
			_, err := parse()
			assert.ErrorContains(t, err, "too many signatures", "expected too many signatures error")

			MaxSignatures = 1
			_, err = parse()
			assert.NoError(t, err, "unexpected error")
		})
	}
}
