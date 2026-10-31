package jose

import (
	"reflect"
	"strings"
	"testing"

	"authelia.com/provider/jose/json"
)

func TestHeaderEqual(t *testing.T) {
	header1 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]any{"kid": "1-2-3-4"},
	}
	header2 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]any{"kid": "1-2-3-4"},
	}
	if !reflect.DeepEqual(header1, header2) {
		t.Fatalf("header1 and header2 are not equal, expected equal")
	}
}

func TestHeaderNotEqual(t *testing.T) {
	header1 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]any{"kid": "1-2-3-4"},
	}
	header2 := Header{
		KeyID:        "1-2-3-4",
		Algorithm:    "test",
		ExtraHeaders: map[HeaderKey]any{"kid": "9-9-9-9"},
	}
	if reflect.DeepEqual(header1, header2) {
		t.Fatalf("header1 and header2 are equal, expected not equal")
	}
}

// getJWK extracts parsed "jwk" from the raw JSON.
func (parsed rawHeader) getJWK() (*JSONWebKey, error) {
	v := parsed[headerJWK]
	if v == nil {
		return nil, nil
	}
	var jwk *JSONWebKey
	err := json.Unmarshal(*v, &jwk)
	if err != nil {
		return nil, err
	}
	return jwk, nil
}

func TestPrivateEPKRejected(t *testing.T) {
	epk := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","d":"AQAB"}`)
	headers := rawHeader{headerEPK: &epk}
	if _, err := headers.getEPK(); err == nil || !strings.Contains(err.Error(), "JWK contains private parameters") {
		t.Errorf("expected private parameters error, got %v", err)
	}
}

func TestMergeHeaders(t *testing.T) {
	var dst, src rawHeader
	err := json.Unmarshal([]byte(`{"empty":"","null":null,"zero":0,"false":false,"set":"dst"}`), &dst)
	if err != nil {
		t.Fatalf("unmarshaling dst: %s", err)
	}
	err = json.Unmarshal([]byte(`{"empty":"src","null":"src","zero":"src","false":"src","set":"src","new":"src"}`), &src)
	if err != nil {
		t.Fatalf("unmarshaling src: %s", err)
	}

	dst.merge(&src)

	for k, want := range map[HeaderKey]string{
		"empty": `""`,
		"null":  `null`,
		"zero":  `0`,
		"false": `false`,
		"set":   `"dst"`,
		"new":   `"src"`,
	} {
		v, ok := dst[k]
		if !ok {
			t.Errorf("merge() dropped %q, want %s", k, want)
			continue
		}
		// A JSON null is stored as a present key with a nil value.
		got := "null"
		if v != nil {
			got = string(*v)
		}
		if got != want {
			t.Errorf("merge() set %q to %s, want %s", k, got, want)
		}
	}
}
