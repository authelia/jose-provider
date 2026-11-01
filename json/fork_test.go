// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers the behaviour that makes this package a fork of the standard
// library's encoding/json, rather than a copy of it. See the package README.

// TestForkCaseSensitive verifies that object member names are matched
// case-sensitively, unlike the standard library which falls back to a
// case-insensitive match.
func TestForkCaseSensitive(t *testing.T) {
	type S struct {
		Alpha string `json:"alpha"`
		Beta  string // no tag; matched by field name
	}

	tests := []struct {
		name      string
		in        string
		wantAlpha string
		wantBeta  string
	}{
		{"exact tag", `{"alpha":"a"}`, "a", ""},
		{"exact field name", `{"Beta":"b"}`, "", "b"},
		{"upper tag does not match", `{"ALPHA":"a"}`, "", ""},
		{"title tag does not match", `{"Alpha":"a"}`, "", ""},
		{"lower field name does not match", `{"beta":"b"}`, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s S
			err := Unmarshal([]byte(tt.in), &s)
			require.NoError(t, err, "Unmarshal error")
			if s.Alpha != tt.wantAlpha || s.Beta != tt.wantBeta {
				assert.Failf(t, "unexpected result", "got {Alpha:%q Beta:%q}, want {Alpha:%q Beta:%q}", s.Alpha, s.Beta, tt.wantAlpha, tt.wantBeta)
			}
		})
	}
}

// TestForkDuplicateKeys verifies that duplicate object members are rejected
// rather than silently resolved to the last occurrence.
func TestForkDuplicateKeys(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ptr  func() any
	}{
		{"struct", `{"alpha":"a","alpha":"b"}`, func() any {
			return &struct {
				Alpha string `json:"alpha"`
			}{}
		}},
		{"interface", `{"alpha":"a","alpha":"b"}`, func() any { var v any; return &v }},
		{"map", `{"alpha":"a","alpha":"b"}`, func() any { return &map[string]string{} }},
		{"nested in object", `{"outer":{"k":1,"k":2}}`, func() any { var v any; return &v }},
		{"nested in array", `[{"k":1,"k":2}]`, func() any { var v any; return &v }},
		{"duplicate null", `{"I":0,"I":null}`, func() any { var v any; return &v }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Unmarshal([]byte(tt.in), tt.ptr())
			require.Error(t, err, "Unmarshal(%s) succeeded, want duplicate key error", tt.in)
			require.Contains(t, err.Error(), "duplicate key", "Unmarshal(%s) error = %v, want a duplicate key error", tt.in, err)
		})
	}
}

// TestForkDuplicateKeysAccepted verifies the fork does not over-reject: the same
// member name at different nesting levels is not a duplicate.
func TestForkDuplicateKeysAccepted(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"b":2}`,
		`{"k":{"k":1}}`,
		`{"a":[{"k":1},{"k":2}]}`,
	} {
		var v any
		err := Unmarshal([]byte(in), &v)
		assert.NoError(t, err, "Unmarshal(%s) error = %v, want nil", in, err)
	}
}

// TestForkNumberType verifies Decoder.SetNumberType, which controls how a JSON
// number is unmarshaled into an interface value.
func TestForkNumberType(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		numberType NumberUnmarshalType
		want       any
	}{
		{"default is float64", `2`, UnmarshalFloat, float64(2)},
		{"json number", `2`, UnmarshalJSONNumber, Number("2")},
		{"int or float: integer", `2`, UnmarshalIntOrFloat, int64(2)},
		{"int or float: fraction", `2.1`, UnmarshalIntOrFloat, float64(2.1)},
		{"int or float: scientific whole", `1.5e2`, UnmarshalIntOrFloat, int64(150)},
		{"int or float: max int64", `9223372036854775807`, UnmarshalIntOrFloat, int64(9223372036854775807)},
		{"int or float: whole with zero fraction", `9007199254740992.000000`, UnmarshalIntOrFloat, int64(9007199254740992)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got any
			dec := NewDecoder(bytes.NewReader([]byte(tt.in)))
			dec.SetNumberType(tt.numberType)
			err := dec.Decode(&got)
			require.NoError(t, err, "Decode error")
			assert.Equal(t, tt.want, got, "Decode(%s) = %#v (%T), want %#v (%T)", tt.in, got, got, tt.want, tt.want)
		})
	}
}

// TestForkUseNumber verifies the deprecated UseNumber remains equivalent to
// SetNumberType(UnmarshalJSONNumber).
func TestForkUseNumber(t *testing.T) {
	var got any
	dec := NewDecoder(bytes.NewReader([]byte(`2`)))
	dec.UseNumber()
	err := dec.Decode(&got)
	require.NoError(t, err, "Decode error")
	want := Number("2")
	assert.Equal(t, want, got, "Decode = %#v, want %#v", got, want)
}

func TestForkUnquoteErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []byte
		err  error
	}{
		{"plain", `"abc"`, []byte("abc"), nil},
		{"escape", `"a\nb"`, []byte("a\nb"), nil},
		{"unicode escape", `"aéb"`, []byte("aéb"), nil},
		{"surrogate pair", `"😀"`, []byte("\U0001f600"), nil},
		{"lone surrogate", `"\ud83d"`, nil, ErrInvalidUnicode},
		{"lone low surrogate", `"\udc00"`, nil, ErrInvalidUnicode},
		{"surrogate then non surrogate", `"\ud83da"`, nil, ErrInvalidUnicode},
		{"invalid utf-8", "\"a\xffb\"", nil, ErrInvalidUnicode},
		{"encoded surrogate", "\"\xed\xa0\x80\"", nil, ErrInvalidUnicode},
		{"unterminated", `"abc`, nil, errPhase},
		{"not a literal", `abc`, nil, errPhase},
		{"bad escape", `"a\xb"`, nil, errPhase},
		{"truncated escape", `"a\`, nil, errPhase},
		{"short unicode escape", `"\u00"`, nil, errPhase},
		{"raw control character", "\"a\x01b\"", nil, errPhase},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := unquoteBytes([]byte(tt.in))
			require.ErrorIs(t, err, tt.err, "unquoteBytes(%q) error = %v, want %v", tt.in, err, tt.err)
			if tt.err != nil {
				return
			}
			assert.Equal(t, tt.want, got, "unquoteBytes(%q) = %q, want %q", tt.in, got, tt.want)
			s, err := unquote([]byte(tt.in))
			if err != nil || s != string(tt.want) {
				assert.Failf(t, "unexpected result", "unquote(%q) = %q, %v, want %q, nil", tt.in, s, err, tt.want)
			}
		})
	}
}

func TestForkUnquoteSizeBounds(t *testing.T) {
	if sized := maxUnquoteInitial + 2*utf8.UTFMax; sized < 0 || sized > math.MaxInt {
		assert.Failf(t, "unexpected result", "maxUnquoteInitial %d overflows when sized: got %d", maxUnquoteInitial, sized)
	}

	if grown := (maxUnquoteRegrow + utf8.UTFMax) * 2; grown < 0 || grown > math.MaxInt {
		assert.Failf(t, "unexpected result", "maxUnquoteRegrow %d overflows when doubled: got %d", maxUnquoteRegrow, grown)
	}
}

func TestForkIndentSizeBounds(t *testing.T) {
	if factored := indentGrowthFactor * maxIndentHint; factored < 0 || factored > math.MaxInt {
		assert.Failf(t, "unexpected result", "maxIndentHint %d overflows when multiplied: got %d", maxIndentHint, factored)
	}
}

func TestForkQuoteChar(t *testing.T) {
	stdlib := func(c byte) string {
		// special cases - different from quoted strings
		if c == '\'' {
			return `'\''`
		}
		if c == '"' {
			return `'"'`
		}

		// use quoted string with different quotation marks
		s := strconv.Quote(string(c))
		return "'" + s[1:len(s)-1] + "'"
	}

	for i := 0; i < 256; i++ {
		c := byte(i)
		got, want := quoteChar(c), stdlib(c)
		assert.Equal(t, want, got, "quoteChar(%#02x) = %s, want %s", c, got, want)
		body := got[1 : len(got)-1]
		assert.Equal(t, strings.Count(body, `\'`), strings.Count(body, `'`), "quoteChar(%#02x) = %s contains an unescaped quote", c, got)
	}
}

func TestForkIntOrFloatKeepsOutOfRangeWholeNumbersAsFloat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want any
	}{
		{"just above max int64", `9223372036854775808`, float64(9223372036854775808)},
		{"large positive exponent", `1e19`, float64(1e19)},
		{"large negative exponent", `-1e19`, float64(-1e19)},
		{"far beyond range", `1e300`, float64(1e300)},
		{"just below min int64", `-9223372036854775809`, float64(-9223372036854775809)},
		{"just below min int64 in exponent form", `-9.223372036854775809e18`, float64(-9223372036854775809)},
		{"fraction just above min int64", `-9223372036854775807.5`, float64(-9223372036854775807.5)},
		{"min int64 in exponent form", `-9.223372036854775808e18`, int64(math.MinInt64)},
		{"min int64 in fractional form", `-9223372036854775808.0`, int64(math.MinInt64)},
		{"min int64", `-9223372036854775808`, int64(math.MinInt64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got any
			dec := NewDecoder(bytes.NewReader([]byte(tt.in)))
			dec.SetNumberType(UnmarshalIntOrFloat)
			err := dec.Decode(&got)
			require.NoError(t, err, "Decode error")
			assert.Equal(t, tt.want, got, "Decode(%s) = %#v (%T), want %#v (%T)", tt.in, got, got, tt.want, tt.want)
		})
	}
}

func TestForkRejectsDuplicateConvertedMapKeys(t *testing.T) {
	tests := []struct {
		name string
		in   string
		into func() any
	}{
		{"int keys", `{"1":"a","01":"b"}`, func() any { return &map[int]string{} }},
		{"uint keys", `{"7":"a","007":"b"}`, func() any { return &map[uint8]string{} }},
		{"text unmarshaler keys", `{"Alg":"a","alg":"b"}`, func() any { return &map[foldedKey]string{} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Unmarshal([]byte(tt.in), tt.into())
			require.Error(t, err, "Unmarshal(%s) accepted keys which convert to the same map key", tt.in)
		})
	}

	t.Run("distinct keys", func(t *testing.T) {
		got := map[int]string{}
		err := Unmarshal([]byte(`{"1":"a","2":"b"}`), &got)
		require.NoError(t, err, "Unmarshal error")
		want := (map[int]string{1: "a", 2: "b"})
		assert.Equal(t, want, got, "Unmarshal = %v, want %v", got, want)
	})

	t.Run("existing entries", func(t *testing.T) {
		got := map[int]string{1: "old"}
		err := Unmarshal([]byte(`{"1":"new"}`), &got)
		require.NoError(t, err, "Unmarshal error")
		assert.Equal(t, "new", got[1])
	})
}

// RFC 7493 Section 2.1.
func TestForkRejectsInvalidUnicodeInSkippedValues(t *testing.T) {
	type target struct {
		A RawMessage
	}

	testCases := map[string]string{
		"UnknownFieldLoneSurrogate": `{"ignored":"\ud800"}`,
		"UnknownFieldInvalidUTF8":   "{\"ignored\":\"a\xffb\"}",
		"UnknownFieldKey":           `{"ignored":{"\udc00":1}}`,
		"RawMessage":                "{\"A\":[\"a\xffb\"]}",
		"RawMessageSurrogate":       `{"A":"\ud83dx"}`,
	}

	for name, input := range testCases {
		t.Run(name, func(t *testing.T) {
			var v target

			err := Unmarshal([]byte(input), &v)
			assert.ErrorIs(t, err, ErrInvalidUnicode, "Unmarshal: got %v, want %v", err, ErrInvalidUnicode)

			err = NewDecoder(strings.NewReader(input)).Decode(&v)
			assert.ErrorIs(t, err, ErrInvalidUnicode, "Decode: got %v, want %v", err, ErrInvalidUnicode)
		})
	}

	var v target

	err := Unmarshal([]byte(`{"ignored":"😀 \\ \" é","A":"😀"}`), &v)
	assert.NoError(t, err, "Unmarshal rejected valid escapes in skipped values")
}

// RFC 7493 Section 2.3.
func TestForkRejectsDuplicateKeysInSkippedValues(t *testing.T) {
	type target struct {
		A RawMessage
	}

	testCases := map[string]string{
		"UnknownField":        `{"ignored":{"k":1,"k":2}}`,
		"UnknownFieldEscaped": `{"ignored":{"k":1,"k":2}}`,
		"UnknownFieldNested":  `{"ignored":[{"x":{"k":1,"k":2}}]}`,
		"RawMessage":          `{"A":{"k":1,"k":2}}`,
		"RawMessageInArray":   `{"A":[{"k":1},{"j":1,"j":2}]}`,
	}

	for name, input := range testCases {
		t.Run(name, func(t *testing.T) {
			var v target

			err := Unmarshal([]byte(input), &v)
			assert.ErrorContains(t, err, "duplicate key", "Unmarshal: got %v, want a duplicate key error", err)

			err = NewDecoder(strings.NewReader(input)).Decode(&v)
			assert.ErrorContains(t, err, "duplicate key", "Decode: got %v, want a duplicate key error", err)
		})
	}

	var v target

	err := Unmarshal([]byte(`{"ignored":[{"k":1},{"k":2}],"A":{"k":{"k":1},"j":"k:"}}`), &v)
	assert.NoError(t, err, "Unmarshal rejected the same key in distinct objects")
}

type foldedKey string

func (k *foldedKey) UnmarshalText(text []byte) error {
	*k = foldedKey(strings.ToLower(string(text)))

	return nil
}
