package tinydns

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
    "encoding/binary"

    "github.com/StackExchange/dnscontrol/models"
)

func deOctalString(s string) []byte {
    var buf []byte
    for x := 0; x < len(s); x++ {
        if s[x] == '\\' {
            // special stuff
            oct := s[x+1:x+4]
            i, err := strconv.ParseUint(oct, 8, 0)
            if err != nil {
                log.Fatalf("Error deOctalizing %v", err)
            }
            buf = append(buf, byte(i))
            x += 3
        } else {
            buf = append(buf, s[x])
        }
    }
    return buf
}

func octalString(buf []byte) string {
    var ret string
    for _, b := range buf {
        ret += fmt.Sprintf("\\%03o", b)
    }
    return ret
}

func uint16ToOctal(u uint16) string {
    buf := make([]byte, 2)
    binary.BigEndian.PutUint16(buf, u)
    return octalString(buf)
}

func octalToUint16(b []byte) uint16 {
    var target uint16
    buf := bytes.NewReader(b)
    binary.Read(buf, binary.BigEndian, &target)
    return target

}

func packName(s string) string {
    segments := strings.Split(s, ".")
    var ret string
    for _, s := range segments {
        ret += fmt.Sprintf("\\%03o%s", len(s), s)
    }
    return ret
}

func unpackName(b []byte) string {
    var name string
    for len(b) > 1 {
        name += string(b[1:b[0]+1]) + "."
        b = b[b[0]+1:]
    }
    return name
}

func lineToRecord(line string, origin string) (models.RecordConfig, bool) {
    rc := models.RecordConfig{
		Original:     line,
	}

    if len(line) == 0 {
        return rc, false
    }
    fields := strings.Split(line[1:],":")
	rc.SetLabelFromFQDN(fields[0], origin)
    maxField := len(fields) - 1
    ttlField := maxField

    switch line[0] {
    case 'Z':
        rc.Type = "SOA"
        if len(fields[3]) == 0 {
            fields[3] = "0"
        }
        rc.Target = strings.Join(fields[1:8], " ")
        ttlField = 8
    case '+', '=':
        rc.Type = "A"
        rc.SetTarget(fields[1])
        ttlField = 2
    case 'C':
        rc.Type = "CNAME"
        rc.SetTarget(fields[1])
        ttlField = 2
    case '@':
        rc.Type = "MX"
        rc.SetTargetMXStrings(fields[3], fields[2])
        ttlField = 4
    case '^':
        rc.Type = "PTR"
        rc.SetTarget(fields[1])
        ttlField = 2
    case '\'':
        rc.Type = "TXT"
        data := fields[1]
        data = strings.ReplaceAll(data, "\072", ":")
        data = strings.ReplaceAll(data, "\015", "\r")
        data = strings.ReplaceAll(data, "\012", "\n")
        rc.SetTargetTXT(data)
        ttlField = 2
    case '&':
        rc.Type = "NS"
        rc.SetTarget(fields[2])
        ttlField = 3
    case ':':
        switch fields[1] {
        case "28":
            rc.Type = "AAAA"
            data := deOctalString(fields[2])
            rc.SetTargetIP(data)
        case "33":
            rc.Type = "SRV"
            data := deOctalString(fields[2])
            name := unpackName(data[6:])
            rc.SetTargetSRV(octalToUint16(data[0:2]), octalToUint16(data[2:4]), octalToUint16(data[4:6]), name)
        case "257":
            rc.Type = "CAA"
            data := deOctalString(fields[2])
            tagLen := 2 + data[1]
            rc.SetTargetCAA(data[0], string(data[2:tagLen]), string(data[tagLen:]))
        case "99":
            return rc, false
        default:
            log.Fatalf("Unimplemented record type %s", fields[1])
        }
    case '#':
        return rc, false
    default:
        log.Fatalf("Unknown record type %c", line[0])
    }

    if ttlField != maxField {
        log.Println("Extra data fields that are not currently supported by dnscontrol")
    }

    ttl, _ := strconv.Atoi(fields[ttlField])
    rc.TTL = uint32(ttl)
    return rc, true
}

// WriteDataFile writes a zone file in tinydns format
func WriteDataFile(w io.Writer, records []*models.RecordConfig, origin string) error {
    for _, r := range records {
        switch r.Type {
        case "SOA":
            //Zfqdn:mname:rname:ser:ref:ret:exp:min:ttl:timestamp:lo
            parts := strings.Fields(r.GetTargetField())
            if parts[2] == "0" {
                parts[2] = ""
            }
            fmt.Fprintf(w, "Z%s:%s:%d\n", r.GetLabelFQDN(), strings.Join(parts, ":"), r.TTL)
        case "A":
            //+fqdn:ip:ttl:timestamp:lo
            fmt.Fprintf(w, "+%s:%s:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.TTL)
        case "AAAA":
            fmt.Fprintf(w, ":%s:28:%s:%d\n", r.GetLabelFQDN(), octalString(r.GetTargetIP()), r.TTL)
        case "CAA":
            fmt.Fprintf(w, ":%s:257:\\%03o\\%03d%s%s:%d\n", r.GetLabelFQDN(), r.CaaFlag, len(r.CaaTag), r.CaaTag, r.GetTargetField(), r.TTL)
        case "CNAME":
            //Cfqdn:p:ttl:timestamp:lo
            fmt.Fprintf(w, "C%s:%s:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.TTL)
        case "MX":
            //@fqdn:ip:x:dist:ttl:timestamp:lo
            fmt.Fprintf(w, "@%s::%s:%d:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.MxPreference, r.TTL)
        case "NAPTR":
            // nothing to do here, yet
        case "NS":
            fmt.Fprintf(w, "&%s::%s:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.TTL)
        case "PTR":
            //^fqdn:p:ttl:timestamp:lo
            fmt.Fprintf(w, "^%s:%s:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.TTL)
        case "SRV":
            fmt.Fprintf(w, ":%s:33:%s%s%s%s:%d\n", r.GetLabelFQDN(), uint16ToOctal(r.SrvPriority), uint16ToOctal(r.SrvWeight), uint16ToOctal(r.SrvPort), packName(r.GetTargetField()), r.TTL)
        case "SSHFP":
            // nothing to do here, yet
        case "TLSA":
            // nothing to do here, yet
        case "TXT":
            //'fqdn:s:ttl:timestamp:lo
            //You may use octal \nnn codes to include arbitrary bytes inside s; for example, \072 is a colon.
            txtData := r.GetTargetField()
            txtData = strings.ReplaceAll(txtData, "\t", "\011")
            txtData = strings.ReplaceAll(txtData, "\r", "\015")
            txtData = strings.ReplaceAll(txtData, "\n", "\012")
            txtData = strings.ReplaceAll(txtData, "\\", "\134")
            txtData = strings.ReplaceAll(txtData, "/", "\057")
            txtData = strings.ReplaceAll(txtData, ":", "\072")
            fmt.Fprintf(w, "'%s:%s:%d\n", r.GetLabelFQDN(), txtData, r.TTL)
        }
    }
    return nil
}
