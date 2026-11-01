// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNumberIsValid(t *testing.T) {
	// From: https://stackoverflow.com/a/13340826
	var jsonNumberRegexp = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`)

	validTests := []string{
		"0",
		"-0",
		"1",
		"-1",
		"0.1",
		"-0.1",
		"1234",
		"-1234",
		"12.34",
		"-12.34",
		"12E0",
		"12E1",
		"12e34",
		"12E-0",
		"12e+1",
		"12e-34",
		"-12E0",
		"-12E1",
		"-12e34",
		"-12E-0",
		"-12e+1",
		"-12e-34",
		"1.2E0",
		"1.2E1",
		"1.2e34",
		"1.2E-0",
		"1.2e+1",
		"1.2e-34",
		"-1.2E0",
		"-1.2E1",
		"-1.2e34",
		"-1.2E-0",
		"-1.2e+1",
		"-1.2e-34",
		"0E0",
		"0E1",
		"0e34",
		"0E-0",
		"0e+1",
		"0e-34",
		"-0E0",
		"-0E1",
		"-0e34",
		"-0E-0",
		"-0e+1",
		"-0e-34",
	}

	for _, test := range validTests {
		assert.True(t, isValidNumber(test), "%s should be valid", test)

		var f float64
		err := Unmarshal([]byte(test), &f)
		assert.NoError(t, err, "%s should be valid but Unmarshal failed", test)

		assert.True(t, jsonNumberRegexp.MatchString(test), "%s should be valid but regexp does not match", test)
	}

	invalidTests := []string{
		"",
		"invalid",
		"1.0.1",
		"1..1",
		"-1-2",
		"012a42",
		"01.2",
		"012",
		"12E12.12",
		"1e2e3",
		"1e+-2",
		"1e--23",
		"1e",
		"e1",
		"1e+",
		"1ea",
		"1a",
		"1.a",
		"1.",
		"01",
		"1.e1",
	}

	for _, test := range invalidTests {
		assert.False(t, isValidNumber(test), "%s should be invalid", test)

		var f float64
		err := Unmarshal([]byte(test), &f)
		assert.Error(t, err, "%s should be invalid but unmarshal wrote %v", test, f)

		assert.False(t, jsonNumberRegexp.MatchString(test), "%s should be invalid but matches regexp", test)
	}
}
