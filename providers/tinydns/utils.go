package tinydns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func deOctalString(s string) (buf []byte) {
	for x := 0; x < len(s); x++ {
		if s[x] == '\\' {
			// special stuff
			var dec uint64
			size := 4
			if len(s)-x < size {
				size = len(s) - x
			}
			for ; size > 1; size-- {
				var err error
				oct := s[x+1 : x+size]
				dec, err = strconv.ParseUint(oct, 8, 0)
				if err == nil {
					break
				}
			}
			if size > 1 {
				buf = append(buf, byte(dec))
				x += size - 1
			} else {
				buf = append(buf, s[x])
			}
		} else {
			buf = append(buf, s[x])
		}
	}
	return
}

func octalString(buf string) string {
	return octalBuf([]byte(buf))
}

func octalBuf(buf []byte) (ret string) {
	for _, b := range buf {
		if b < 40 || b > 126 {
			ret += fmt.Sprintf("\\%03o", b)
		} else {
			ret += string(b)
		}
	}
	return
}

func uint16ToOctal(u uint16) string {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, u)
	return octalBuf(buf)
}

func nameToOctalPack(s string) (ret string) {
	segments := strings.Split(s, ".")
	for _, s := range segments {
		ret += fmt.Sprintf("\\%03o%s", len(s), s)
	}
	return
}

func byteToUint16(b []byte) (u uint16) {
	buf := bytes.NewReader(b)
	binary.Read(buf, binary.BigEndian, &u)
	return
}

func escapeString(s string) (e string) {
	e = strings.ReplaceAll(s, "\\", "\\134")
	e = strings.ReplaceAll(e, "/", "\\057")
	e = strings.ReplaceAll(e, ":", "\\072")
	return
}

func unpackName(b []byte) (name string) {
	for len(b) > 1 {
		var label string
		label, b = unpackString(b)
		name += label + "."
	}
	return
}

func unpackString(b []byte) (string, []byte) {
	return string(b[1 : b[0]+1]), b[b[0]+1:]
}

func parseTinydnsName(fqdn, name, sub string) string {
	if !strings.Contains(name, ".") {
		return strings.Join([]string{name, sub, fqdn}, ".")
	}
	return name
}

func parseTTL(t string) uint32 {
	ttl, _ := strconv.ParseUint(t, 10, 32)
	return uint32(ttl)
}
