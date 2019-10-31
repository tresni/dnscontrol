package tinydns

import (
	"testing"
)

func TestOctalString(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	s := octalString(b)
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
	e := escapeString(s)
	if string(deOctalString(e)) != s {
		t.Error("Can't encode/decode a string")
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
		t.Error("Incorrectt parsing of integer string")
	}
	if parseTTL("4294967295") != uint32(4294967295) {
		t.Error("Incorrect parsing of uint32 max")
	}
}
