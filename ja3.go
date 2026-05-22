// Package ja3 computes JA3 TLS client fingerprints from raw ClientHello bytes.
//
// JA3 was developed by Salesforce and is released under the BSD-2-Clause license.
// This implementation is a pure-Go, zero-CGO, zero-dependency port of the algorithm.
//
// Reference: https://github.com/salesforce/ja3
package ja3

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// DigestHex returns the JA3 fingerprint (32-char MD5 hex) from a raw TLS
// record buffer that starts at the beginning of a ClientHello. Returns ""
// if the buffer does not contain a valid ClientHello.
func DigestHex(buf []byte) string {
	raw := Bare(buf)
	if raw == nil {
		return ""
	}
	sum := md5.Sum(raw)
	return hex.EncodeToString(sum[:])
}

// Bare returns the JA3 bare string (before hashing) from a raw TLS record
// buffer. The format is:
//
//	TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
//
// GREASE values (RFC 8701) are filtered from all fields.
// Returns nil if the buffer cannot be parsed.
func Bare(buf []byte) []byte {
	hello, ok := parseClientHello(buf)
	if !ok {
		return nil
	}

	var b []byte
	b = strconv.AppendInt(b, int64(hello.version), 10)
	b = append(b, ',')
	b = appendUint16List(b, hello.ciphers)
	b = append(b, ',')
	b = appendUint16List(b, hello.extensions)
	b = append(b, ',')
	b = appendUint16List(b, hello.groups)
	b = append(b, ',')
	b = appendUint8List(b, hello.points)
	return b
}

// ── GREASE filtering ─────────────────────────────────────────────────────────

// isGREASE reports whether v is a GREASE value (RFC 8701).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// ── ClientHello field extraction ─────────────────────────────────────────────

type clientHelloFields struct {
	version    uint16
	ciphers    []uint16
	extensions []uint16
	groups     []uint16
	points     []uint8
}

func parseClientHello(buf []byte) (clientHelloFields, bool) {
	var h clientHelloFields

	// TLS record header: ContentType(1) + Version(2) + Length(2)
	if len(buf) < 5 || buf[0] != 0x16 {
		return h, false
	}
	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if recLen > len(buf)-5 {
		recLen = len(buf) - 5
	}
	data := buf[5 : 5+recLen]

	// Handshake header: Type(1) + Length(3)
	if len(data) < 4 || data[0] != 0x01 {
		return h, false
	}
	data = data[4:]

	// ClientHello: Version(2) + Random(32)
	if len(data) < 34 {
		return h, false
	}
	h.version = binary.BigEndian.Uint16(data[0:2])
	data = data[34:]

	// SessionID: Length(1) + ID
	if len(data) < 1 {
		return h, false
	}
	sessLen := int(data[0])
	data = data[1:]
	if len(data) < sessLen {
		return h, false
	}
	data = data[sessLen:]

	// CipherSuites: Length(2) + suites
	if len(data) < 2 {
		return h, false
	}
	csLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < csLen || csLen%2 != 0 {
		return h, false
	}
	for i := 0; i < csLen; i += 2 {
		v := binary.BigEndian.Uint16(data[i : i+2])
		if !isGREASE(v) {
			h.ciphers = append(h.ciphers, v)
		}
	}
	data = data[csLen:]

	// CompressionMethods: Length(1) + methods
	if len(data) < 1 {
		return h, false
	}
	cmLen := int(data[0])
	data = data[1:]
	if len(data) < cmLen {
		return h, false
	}
	data = data[cmLen:]

	// Extensions: Length(2) — optional; absence is valid
	if len(data) < 2 {
		return h, true
	}
	extBlockLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < extBlockLen {
		extBlockLen = len(data)
	}
	data = data[:extBlockLen]

	for len(data) >= 4 {
		extType := binary.BigEndian.Uint16(data[0:2])
		extLen := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if len(data) < extLen {
			break
		}
		extData := data[:extLen]
		data = data[extLen:]

		if isGREASE(extType) {
			continue
		}
		h.extensions = append(h.extensions, extType)

		switch extType {
		case 0x000a: // supported_groups
			h.groups = parseSupportedGroups(extData)
		case 0x000b: // ec_point_formats
			h.points = parsePointFormats(extData)
		}
	}

	return h, true
}

// parseSupportedGroups decodes extension 0x000a (supported_groups).
func parseSupportedGroups(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if len(b) < listLen || listLen%2 != 0 {
		return nil
	}
	var out []uint16
	for i := 0; i < listLen; i += 2 {
		v := binary.BigEndian.Uint16(b[i : i+2])
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// parsePointFormats decodes extension 0x000b (ec_point_formats).
func parsePointFormats(b []byte) []uint8 {
	if len(b) < 1 {
		return nil
	}
	listLen := int(b[0])
	b = b[1:]
	if len(b) < listLen {
		return nil
	}
	out := make([]uint8, listLen)
	copy(out, b[:listLen])
	return out
}

// ── Formatting helpers ────────────────────────────────────────────────────────

func appendUint16List(b []byte, vals []uint16) []byte {
	for i, v := range vals {
		if i > 0 {
			b = append(b, '-')
		}
		b = strconv.AppendUint(b, uint64(v), 10)
	}
	return b
}

func appendUint8List(b []byte, vals []uint8) []byte {
	for i, v := range vals {
		if i > 0 {
			b = append(b, '-')
		}
		b = strconv.AppendUint(b, uint64(v), 10)
	}
	return b
}
