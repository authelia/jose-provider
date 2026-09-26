# Safe JSON

This package contains a fork of the `encoding/json` package from Go 1.26.6.

It tracks the changes originally made by [go-jose](https://github.com/go-jose/go-jose/tree/main/json), which forked
`encoding/json` from Go 1.6. Those changes have been reapplied on top of the newer standard library implementation
rather than carrying the Go 1.6 code forward.

The following changes were made:

- Object deserialization uses case-sensitive member name matching instead of
  [case-insensitive matching](https://www.ietf.org/mail-archive/web/json/current/msg03763.html). This is to avoid
  differences in the interpretation of JOSE messages between go-jose and libraries written in other languages.
- When deserializing a JSON object, we check for duplicate keys and reject the input whenever we detect a duplicate.
  Rather than trying to work with malformed data, we prefer to reject it right away.
- Strings must be valid Unicode. Decoding a string with invalid UTF-8 or an unpaired UTF-16 surrogate escape returns
  `ErrInvalidUnicode`, and encoding a string with invalid UTF-8 returns an `InvalidUTF8Error`, rather than either
  replacing the invalid sequence with U+FFFD. [RFC 7493](https://www.rfc-editor.org/rfc/rfc7493#section-2.1) excludes
  both from I-JSON, and replacing them lets distinct strings on the wire decode as the same value.
- `Decoder.SetNumberType` selects how a JSON number is unmarshaled into an interface value: as a `float64`, as a
  `Number`, or as an `int64` when the value is a whole number. `Decoder.UseNumber` is retained as a deprecated alias for
  the `Number` behaviour.

Upstream tests that assert the replaced behaviour have been adjusted, and the fork's own behaviour is covered by
`fork_test.go`.
