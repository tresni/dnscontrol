package tinydns

import (
	"testing"
)

func TestOctalString(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	s := octalBuf(b)
	if s != "\\001\\002\\003\\004\\005" {
		t.Errorf("Bytes not properly encoded: %s", s)
	}
}

func TestDeoctalString(t *testing.T) {
	s := "abc\\1001"
	b := deOctalString(s)
	if b[3] != 'd' && b[4] != '1' {
		t.Error("Improperly decoded octal String")
	}
	s = "abc\\z"
	b = deOctalString(s)
	if s != string(b) {
		t.Error("Improperly handling non-octal")
	}
}

func TestUint16ToOctal(t *testing.T) {
	o1 := uint16ToOctal(1)
	o65535 := uint16ToOctal(65535)
	if o1 != "\\000\\001" {
		t.Error("Improperly encoded 1")
	}
	if o65535 != "\\377\\377" {
		t.Error("Improperly encoded 65535")
	}

	b := deOctalString(o1)
	if byteToUint16(b) != 1 {
		t.Error("Improperly decoded 1")
	}

	b = deOctalString(o65535)
	if byteToUint16(b) != 65535 {
		t.Error("Improperly decoded 65535")
	}
}

func TestOctalPackName(t *testing.T) {
	encoded := "\\003www\\007example\\003com"
	fqdn := "www.example.com"

	e := nameToOctalPack(fqdn)
	if e != encoded {
		t.Errorf("Failed to properly pack www.example.com: %s", e)
	}

}

func TestPackedName(t *testing.T) {
	encoded := []byte("\003www\007example\003com\000")
	s, r := unpackString(encoded)
	if s != "www" && r[0] != '\\' {
		t.Error("Failed to parse packed www.example.com")
	}
	s, r = unpackString(r)
	if s != "example" && r[0] != '\\' {
		t.Error("Failed to parse packed example.com")
	}

	n := unpackName(encoded)
	if n != "www.example.com." {
		t.Errorf("Unable to unpack name: %s", n)
	}
}

func TestEscapeString(t *testing.T) {
	s := "colons(:) and newlines (\r\n) need to be escaped."
	e := octalString(escapeString(s))
	if string(deOctalString(e)) != s {
		t.Errorf("Can't encode/decode a string %s", e)
	}
}

func TestParseTinydnsName(t *testing.T) {
	if parseTinydnsName("example", "a", "ns") != "a.ns.example" {
		t.Error("Incorrect response for simple parse")
	}
	if parseTinydnsName("example", "a.", "ns") != "a." {
		t.Error("Inccorect response for dotted name")
	}
}

func TestParseTTL(t *testing.T) {
	if parseTTL("1") != uint32(1) {
		t.Error("Incorrect parsing of integer string")
	}
	if parseTTL("4294967295") != uint32(4294967295) {
		t.Error("Incorrect parsing of uint32 max")
	}
}

func TestBinaryData(t *testing.T) {
	s := "\x44\x4e\x53\x43\x00\x01\x00\x00\xbf\x8f\x81\xb9" +
		"\x2b\x6e\xce\xef\xa3\x1a\x25\x0e\xb8\xb2\x1d\xa7\x1b\xb2\x97\xf5" +
		"\x22\x3e\x77\xae\xe1\x04\x66\xed\xdc\x19\x03\x59\xc9\x0c\xe5\x6a" +
		"\x73\xbe\x19\x3a\x62\xe8\x1a\xea\xe7\x31\x14\x02\xb9\x76\x8e\x1a" +
		"\x79\x3b\xf5\x00\xde\x8e\xaa\x35\x56\x66\xcf\x09\x6f\x08\x19\xa2" +
		"\xe0\x63\x60\xb3\x24\x99\xe5\x34\x0c\x0e\x8b\x30\xf5\xcf\xb1\x76" +
		"\xdf\x19\x2b\xc7\x2c\x52\x81\x32\x88\x95\x54\x2a\x71\x6a\x7a\x6d" +
		"\x6d\x48\x6a\x53\x5f\x90\xd2\x47\x5f\x90\xd2\x47\x61\x72\x05\xc7"

	x := octalString(s)
	y := string(deOctalString(x))
	if s != y {
		t.Error("Unable to handle binary data")
	}
}
