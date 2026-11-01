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
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeflateRoundtrip(t *testing.T) {
	original := []byte("Lorem ipsum dolor sit amet")

	compressed, err := deflate(original)
	if err != nil {
		panic(err)
	}

	output, err := inflate(compressed)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, original, output, "Input and output do not match")
}

func TestInvalidCompression(t *testing.T) {
	_, err := compress("XYZ", []byte{})
	assert.Error(t, err, "should not accept invalid algorithm")

	_, err = decompress("XYZ", []byte{})
	assert.Error(t, err, "should not accept invalid algorithm")

	_, err = decompress(DEFLATE, []byte{1, 2, 3, 4})
	assert.Error(t, err, "should not accept invalid data")
}

// TestLargeZip tests that we can decompress a large input, so long as its
// compression ratio is reasonable.
func TestLargeZip(t *testing.T) {
	input := new(bytes.Buffer)
	_, err := io.CopyN(input, rand.Reader, 251_000)
	require.NoError(t, err, "generating input")
	compressed, err := compress(DEFLATE, input.Bytes())
	assert.NoError(t, err, "compressing")
	t.Logf("compression ratio: %g", float64(len(input.Bytes()))/float64(len(compressed)))
	_, err = decompress(DEFLATE, compressed)
	assert.NoError(t, err, "decompressing large input with low compression ratio")
}

func TestZipBomb(t *testing.T) {
	input := strings.Repeat("a", 251_000)
	compressed, err := compress(DEFLATE, []byte(input))
	assert.NoError(t, err, "compressing")
	t.Logf("compression ratio: %d %g", len(compressed), float64(len(input))/float64(len(compressed)))
	out, err := decompress(DEFLATE, compressed)
	assert.Error(t, err, "expected error decompressing zip bomb, got none. output size %d", len(out))
}

func TestByteBufferTrim(t *testing.T) {
	buf := newBufferFromInt(1)
	assert.Equal(t, []byte{1}, buf.data, "Byte buffer for integer '1' should contain [0x01]")

	buf = newBufferFromInt(65537)
	assert.Equal(t, []byte{1, 0, 1}, buf.data, "Byte buffer for integer '65537' should contain [0x01, 0x00, 0x01]")
}

func TestFixedSizeBuffer(t *testing.T) {
	data0 := []byte{}
	data1 := []byte{1}
	data2 := []byte{1, 2}
	data3 := []byte{1, 2, 3}
	data4 := []byte{1, 2, 3, 4}

	buf0 := newFixedSizeBuffer(data0, 4)
	buf1 := newFixedSizeBuffer(data1, 4)
	buf2 := newFixedSizeBuffer(data2, 4)
	buf3 := newFixedSizeBuffer(data3, 4)
	buf4 := newFixedSizeBuffer(data4, 4)

	assert.Equal(t, []byte{0, 0, 0, 0}, buf0.data, "Invalid padded buffer for buf0")
	assert.Equal(t, []byte{0, 0, 0, 1}, buf1.data, "Invalid padded buffer for buf1")
	assert.Equal(t, []byte{0, 0, 1, 2}, buf2.data, "Invalid padded buffer for buf2")
	assert.Equal(t, []byte{0, 1, 2, 3}, buf3.data, "Invalid padded buffer for buf3")
	assert.Equal(t, []byte{1, 2, 3, 4}, buf4.data, "Invalid padded buffer for buf4")
}

func TestFixedSizeBufferTooLarge(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("should not be able to create fixed size buffer with oversized data")
		}
	}()

	newFixedSizeBuffer(make([]byte, 2), 1)
}

func TestNilByteBuffer(t *testing.T) {
	var buf *byteBuffer

	if got := buf.bytes(); got != nil {
		t.Errorf("bytes() = %v, want nil", got)
	}
	if got := buf.base64(); got != "" {
		t.Errorf("base64() = %q, want empty string", got)
	}
	if got := buf.bigInt(); got.Sign() != 0 {
		t.Errorf("bigInt() = %s, want 0", got)
	}
	if got, err := buf.toInt(); got != 0 || err != nil {
		t.Errorf("toInt() = %d, %v, want 0, nil", got, err)
	}

	got, err := buf.MarshalJSON()
	assert.NoError(t, err, "MarshalJSON() returned error")
	assert.Equal(t, `""`, string(got), "MarshalJSON() = %s, want %s", got, `""`)
}
