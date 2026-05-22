package ja3_test

import (
	"encoding/hex"
	"testing"

	ja3 "github.com/Allod-Solutions/go-ja3"
)

// buildClientHello assembles a minimal TLS record containing a ClientHello.
//   - version: ClientHello legacy version (e.g. 0x0303)
//   - ciphers: cipher suite values
//   - extTypes: additional extension types with empty bodies
//   - groups: supported_groups extension values (nil = omit)
//   - points: ec_point_formats extension values (nil = omit)
func buildClientHello(version uint16, ciphers []uint16, extTypes []uint16, groups []uint16, points []uint8) []byte {
	put16 := func(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

	var exts []byte
	for _, t := range extTypes {
		exts = put16(exts, t)
		exts = put16(exts, 0)
	}
	if groups != nil {
		body := make([]byte, 2+len(groups)*2)
		body[0] = byte(len(groups) * 2 >> 8)
		body[1] = byte(len(groups) * 2)
		for i, g := range groups {
			body[2+i*2] = byte(g >> 8)
			body[2+i*2+1] = byte(g)
		}
		exts = put16(exts, 0x000a)
		exts = put16(exts, uint16(len(body)))
		exts = append(exts, body...)
	}
	if points != nil {
		body := append([]byte{byte(len(points))}, points...)
		exts = put16(exts, 0x000b)
		exts = put16(exts, uint16(len(body)))
		exts = append(exts, body...)
	}

	var ch []byte
	ch = put16(ch, version)
	ch = append(ch, make([]byte, 32)...) // random
	ch = append(ch, 0)                   // session ID length
	ch = put16(ch, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		ch = put16(ch, c)
	}
	ch = append(ch, 1, 0) // compression: length=1, null

	if len(exts) > 0 {
		ch = put16(ch, uint16(len(exts)))
		ch = append(ch, exts...)
	}

	hdr := []byte{0x01, byte(len(ch) >> 16), byte(len(ch) >> 8), byte(len(ch))}
	hs := append(hdr, ch...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func TestBare(t *testing.T) {
	buf := buildClientHello(
		0x0303,
		[]uint16{0x002f, 0x0035},         // AES128-SHA, AES256-SHA
		[]uint16{0x0000},                 // SNI (groups/points come from dedicated params)
		[]uint16{0x0017, 0x0018},          // secp256r1, secp384r1
		[]uint8{0x00},                     // uncompressed
	)

	// Expected: 771 = 0x0303; ciphers=47,53; extensions=0,10,11; groups=23,24; points=0
	want := "771,47-53,0-10-11,23-24,0"
	if got := string(ja3.Bare(buf)); got != want {
		t.Errorf("Bare = %q, want %q", got, want)
	}
}

func TestDigestHex(t *testing.T) {
	buf := buildClientHello(0x0303, []uint16{0x002f}, []uint16{0x0000}, []uint16{0x0017}, []uint8{0x00})
	fp := ja3.DigestHex(buf)
	if len(fp) != 32 {
		t.Fatalf("expected 32-char hex, got %d: %q", len(fp), fp)
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Errorf("not valid hex: %v", err)
	}
	if fp2 := ja3.DigestHex(buf); fp2 != fp {
		t.Errorf("not deterministic: %q vs %q", fp, fp2)
	}
}

func TestGREASEFiltered(t *testing.T) {
	buf := buildClientHello(
		0x0303,
		[]uint16{0x0a0a, 0x002f, 0x1a1a}, // two GREASE + AES128-SHA
		[]uint16{0x2a2a, 0x0000},          // one GREASE ext + SNI
		nil, nil,
	)
	// GREASE values must be absent; no groups or points.
	want := "771,47,0,,"
	if got := string(ja3.Bare(buf)); got != want {
		t.Errorf("Bare = %q, want %q", got, want)
	}
}

func TestNoExtensions(t *testing.T) {
	buf := buildClientHello(0x0303, []uint16{0x002f}, nil, nil, nil)
	want := "771,47,,,"
	if got := string(ja3.Bare(buf)); got != want {
		t.Errorf("Bare = %q, want %q", got, want)
	}
}

func TestInvalidInputsReturnEmpty(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"not tls", []byte("GET / HTTP/1.1\r\n")},
		{"truncated", []byte{0x16, 0x03, 0x01}},
		{"wrong handshake type", func() []byte {
			b := buildClientHello(0x0303, []uint16{0x002f}, nil, nil, nil)
			b[5] = 0x02 // ServerHello, not ClientHello
			return b
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ja3.DigestHex(tc.buf); got != "" {
				t.Errorf("expected empty fingerprint, got %q", got)
			}
		})
	}
}

func TestDistinctClients(t *testing.T) {
	a := buildClientHello(0x0303, []uint16{0x002f}, nil, nil, nil)
	b := buildClientHello(0x0303, []uint16{0x0035}, nil, nil, nil)
	fa := ja3.DigestHex(a)
	fb := ja3.DigestHex(b)
	if fa == "" || fb == "" {
		t.Fatal("expected non-empty fingerprints")
	}
	if fa == fb {
		t.Errorf("different ciphers must yield different fingerprints; both = %q", fa)
	}
}
