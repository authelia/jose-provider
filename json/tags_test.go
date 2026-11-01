// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagParsing(t *testing.T) {
	name, opts := parseTag("field,foobar,foo")
	require.Equal(t, "field", name, "name = %q, want field", name)
	for _, tt := range []struct {
		opt  string
		want bool
	}{
		{"foobar", true},
		{"foo", true},
		{"bar", false},
	} {
		assert.Equal(t, tt.want, opts.Contains(tt.opt), "Contains(%q) = %v, want %v", tt.opt, !tt.want, tt.want)
	}
}
