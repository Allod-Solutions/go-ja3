# go-ja3

Pure-Go, zero-CGO, zero-dependency implementation of the [JA3](https://github.com/salesforce/ja3) TLS client fingerprinting algorithm.

## Features

- No CGO, no `libpcap`, no `gopacket` — cross-compiles to any GOOS/GOARCH
- Single input: raw TLS record bytes (starting at the ClientHello)
- Returns the bare JA3 string and/or the MD5 hex fingerprint
- GREASE values (RFC 8701) are filtered automatically

## Usage

```go
import ja3 "github.com/Allod-Solutions/go-ja3"

// fp is the 32-char MD5 hex fingerprint, or "" on parse failure.
fp := ja3.DigestHex(rawTLSBytes)

// Bare returns the pre-hash string, e.g. "771,47-53,0-10-11,23-24,0"
bare := ja3.Bare(rawTLSBytes)
```

`rawTLSBytes` must start at the TLS record header (byte 0 = `0x16`), which is exactly the data you receive from a client before any proxying.

## Algorithm

JA3 concatenates decimal values of five ClientHello fields — TLS version, cipher suites, extensions, elliptic curves, and elliptic curve point formats — joined by commas, with hyphens separating values within each field. The string is then MD5-hashed.

```
SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
```

## License

BSD 2-Clause. The JA3 algorithm was developed by Salesforce (also BSD-2-Clause).
