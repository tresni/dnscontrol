package tinydns

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/miekg/dns"
)

func deOctalString(s string) []byte {
	var buf []byte
	for x := 0; x < len(s); x++ {
		if s[x] == '\\' {
			// special stuff
			oct := s[x+1 : x+4]
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

func nameToOctalPack(s string) string {
	segments := strings.Split(s, ".")
	var ret string
	for _, s := range segments {
		ret += fmt.Sprintf("\\%03o%s", len(s), s)
	}
	return ret
}

func byteToUint16(b []byte) uint16 {
	var target uint16
	buf := bytes.NewReader(b)
	binary.Read(buf, binary.BigEndian, &target)
	return target
}

func escapeString(s string) (e string) {
	e = strings.ReplaceAll(s, "\t", "\\011")
	e = strings.ReplaceAll(e, "\r", "\\015")
	e = strings.ReplaceAll(e, "\n", "\\012")
	e = strings.ReplaceAll(e, "\\", "\\134")
	e = strings.ReplaceAll(e, "/", "\\057")
	e = strings.ReplaceAll(e, ":", "\\072")
	return
}

func unpackName(b []byte) string {
	var name string
	for len(b) > 1 {
		var label string
		label, b = unpackString(b)
		name += label + "."
	}
	return name
}

func unpackString(b []byte) (string, []byte) {
	return string(b[1 : b[0]+1]), b[b[0]+1:]
}

// ReadError is an error reading the tinydns data file
type ReadError struct {
	err string
}

func (e *ReadError) Error() (s string) {
	s += e.err
	return
}

func parseDataFile(zonename string, r io.Reader, rrs chan dns.RR) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if err := lineToRecord(scanner.Text(), zonename, rrs); err != nil {
			log.Fatalf(err.Error())
		}
	}
	close(rrs)
}

// ReadDataFile reads a tinydns data file and returns an array of zones & records
func ReadDataFile(zonename string, r io.Reader) []dns.RR {
	var foundRecords []dns.RR
	rrs := make(chan dns.RR)

	go parseDataFile(zonename, r, rrs)

	for rec := range rrs {
		foundRecords = append(foundRecords, rec)
	}
	// Get each SOA records
	// create Zone for each SOA record
	// add records to zone based on longest string match
	return foundRecords
}

func createARecord(fqdn, ip string, ttl uint32) dns.RR {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
	r.A = net.ParseIP(ip)
	return r
}

func createNSRecord(fqdn, nameserver string, ttl uint32) dns.RR {
	r := new(dns.NS)
	r.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = nameserver
	return r
}

func createSOARecord(fqdn, nameserver, mbox string, ttl uint32) dns.RR {
	r := new(dns.SOA)
	r.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = nameserver
	r.Mbox = mbox
	return r
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

func lineToRecord(line, origin string, rrs chan dns.RR) error {
	var r dns.RR

	if len(line) == 0 {
		return nil
	}
	fields := strings.Split(line[1:], ":")
	fqdn := fields[0]
	maxField := len(fields) - 1
	ttlField := maxField

	if !dns.IsSubDomain(origin, fqdn) {
		return nil
	}

	switch line[0] {
	case '.':
		// fqdn:ip:x:ttl:timestamp:lo
		if fqdn != origin {
			return nil
		}
		nameserver := parseTinydnsName(fqdn, fields[2], "ns")
		ttl := parseTTL(fields[3])

		if len(fields[1]) != 0 && dns.IsSubDomain(origin, nameserver) {
			rrs <- createARecord(nameserver, fields[1], ttl)
		}
		rrs <- createSOARecord(fqdn, nameserver, "hostmaster."+fqdn, ttl)
		rrs <- createNSRecord(fqdn, nameserver, ttl)
		ttlField = 3
	case 'Z':
		if fqdn != origin {
			return nil
		}
		r = createSOARecord(fqdn, fields[1], fields[2], 0)
		for i := 3; i <= 8; i++ {
			var v uint32
			if len(fields[i]) > 0 {
				val, err := strconv.ParseUint(fields[i], 10, 32)
				if err != nil {
					return &ReadError{"bad SOA" + err.Error()}
				}
				v = uint32(val)
			}
			switch i {
			case 3:
				r.(*dns.SOA).Serial = v
			case 4:
				r.(*dns.SOA).Refresh = v
			case 5:
				r.(*dns.SOA).Retry = v
			case 6:
				r.(*dns.SOA).Expire = v
			case 7:
				r.(*dns.SOA).Minttl = v
			case 8:
				r.(*dns.SOA).Hdr.Ttl = v
			}
		}
		rrs <- r
		ttlField = 8
	case '=':
		// TODO: implement PTR reverse record for A, going to require returning
		// an array of dns.RR, seems shitty since we are only returning 2 values
		// in this specific case...
		fallthrough
	case '+':
		r := createARecord(fqdn, fields[1], parseTTL(fields[2]))
		rrs <- r
		ttlField = 2
	case 'C':
		r = new(dns.CNAME)
		r.(*dns.CNAME).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: parseTTL(fields[2])}
		r.(*dns.CNAME).Target = fields[1]
		rrs <- r
		ttlField = 2
	case '@':
		ttl := parseTTL(fields[4])
		mx := parseTinydnsName(fqdn, fields[2], "mx")
		if len(fields[1]) > 0 {
			rrs <- createARecord(mx, fields[1], ttl)
		}
		r = new(dns.MX)
		r.(*dns.MX).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl}
		val, err := strconv.ParseUint(fields[3], 10, 16)
		if err != nil {
			return &ReadError{"bad MX " + err.Error()}
		}
		r.(*dns.MX).Preference = uint16(val)
		r.(*dns.MX).Mx = mx
		rrs <- r
	case '^':
		r = new(dns.PTR)
		ttl := parseTTL(fields[2])
		r.(*dns.PTR).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.(*dns.PTR).Ptr = fields[1]
		rrs <- r
		ttlField = 2
	case '\'':
		r = new(dns.TXT)
		ttl := parseTTL(fields[2])
		r.(*dns.TXT).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
		data := string(deOctalString(fields[1]))
		data = strings.ReplaceAll(data, "\r", "")
		r.(*dns.TXT).Txt = strings.Split(data, "\n")
		rrs <- r
		ttlField = 2
	case '&':
		ttl := parseTTL(fields[3])
		nameserver := parseTinydnsName(fqdn, fields[2], "ns")
		if len(fields[1]) != 0 && dns.IsSubDomain(origin, nameserver) {
			rrs <- createARecord(nameserver, fields[1], ttl)
		}
		rrs <- createNSRecord(fqdn, nameserver, ttl)
		ttlField = 3
	case ':':
		data := deOctalString(fields[2])
		ttl := parseTTL(fields[3])
		switch fields[1] {
		case "28":
			r = new(dns.AAAA)
			r.(*dns.AAAA).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
			r.(*dns.AAAA).AAAA = data
		case "33":
			r = new(dns.SRV)
			r.(*dns.SRV).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}
			r.(*dns.SRV).Priority = byteToUint16(data[0:2])
			r.(*dns.SRV).Weight = byteToUint16(data[2:4])
			r.(*dns.SRV).Port = byteToUint16(data[4:6])
			r.(*dns.SRV).Target = unpackName(data[6:])
		case "35":
			r = new(dns.NAPTR)
			r.(*dns.NAPTR).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNAPTR, Class: dns.ClassINET, Ttl: ttl}
			r.(*dns.NAPTR).Order = byteToUint16(data[0:2])
			r.(*dns.NAPTR).Preference = byteToUint16(data[2:4])
			var i int
			for i, data = 0, data[4:]; i < 3; i++ {
				var v string
				v, data = unpackString(data)
				switch i {
				case 0:
					r.(*dns.NAPTR).Flags = v
				case 1:
					r.(*dns.NAPTR).Service = v
				case 2:
					r.(*dns.NAPTR).Regexp = v
				}
			}
			r.(*dns.NAPTR).Replacement = unpackName(data)
		case "44":
			r = new(dns.SSHFP)
			r.(*dns.SSHFP).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeSSHFP, Class: dns.ClassINET, Ttl: ttl}
			r.(*dns.SSHFP).Algorithm = data[0]
			r.(*dns.SSHFP).Type = data[1]
			r.(*dns.SSHFP).FingerPrint = hex.EncodeToString(deOctalString(string(data[2:])))
		case "52":
			r = new(dns.TLSA)
			r.(*dns.TLSA).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTLSA, Class: dns.ClassINET, Ttl: ttl}
			r.(*dns.TLSA).Usage = data[0]
			r.(*dns.TLSA).Selector = data[1]
			r.(*dns.TLSA).MatchingType = data[2]
			r.(*dns.TLSA).Certificate = string(data[3:])
		case "99":
			log.Println("Ignoring SPF records for the time being")
			return nil
		case "257":
			r = new(dns.CAA)
			r.(*dns.CAA).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: ttl}
			tagLen := 2 + data[1]
			r.(*dns.CAA).Flag = data[0]
			r.(*dns.CAA).Tag = string(data[2:tagLen])
			r.(*dns.CAA).Value = string(data[tagLen:])
		default:
			return &ReadError{"Unimplemented record type " + string(fields[1])}
		}
		rrs <- r
	case '#', '-':
		return nil
	default:
		return &ReadError{"Unknown record type " + string(line[0])}
	}

	if ttlField != maxField {
		log.Println("Extra data fields detected that are not currently supported by dnscontrol")
	}
	return nil
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
			fmt.Fprintf(w, ":%s:35:%s%s\\%03o%s\\%03o%s\\%03o%s%s:%d\n",
				r.GetLabelFQDN(),
				uint16ToOctal(r.NaptrOrder),
				uint16ToOctal(r.NaptrPreference),
				len(r.NaptrFlags), r.NaptrFlags,
				len(r.NaptrService), escapeString(r.NaptrService),
				len(r.NaptrRegexp), escapeString(r.NaptrRegexp),
				nameToOctalPack(r.GetTargetField()),
				r.TTL)
		case "NS":
			fmt.Fprintf(w, "&%s::%s:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.TTL)
		case "PTR":
			//^fqdn:p:ttl:timestamp:lo
			fmt.Fprintf(w, "^%s:%s:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.TTL)
		case "SRV":
			fmt.Fprintf(w, ":%s:33:%s%s%s%s:%d\n", r.GetLabelFQDN(), uint16ToOctal(r.SrvPriority), uint16ToOctal(r.SrvWeight), uint16ToOctal(r.SrvPort), nameToOctalPack(r.GetTargetField()), r.TTL)
		case "SSHFP":
			hex, err := hex.DecodeString(r.GetTargetField())
			if err != nil {
				log.Fatalf("Unable to encode %s as hex string", r.GetTargetField())
			}
			fmt.Fprintf(w, ":%s:44:\\%03o\\%03o%s:%d\n", r.GetLabelFQDN(), r.SshfpAlgorithm, r.SshfpFingerprint, octalString(hex), r.TTL)
		case "TLSA":
			fmt.Fprintf(w, ":%s:52:\\%03o\\%03o\\%03o%s:%d\n", r.GetLabelFQDN(), r.TlsaUsage, r.TlsaSelector, r.TlsaMatchingType, r.GetTargetField(), r.TTL)
		case "TXT":
			//'fqdn:s:ttl:timestamp:lo
			//You may use octal \nnn codes to include arbitrary bytes inside s; for example, \072 is a colon.
			//We can write multiple records, but we can't read them as tiny doesn't differentiate
			fmt.Fprintf(w, "'%s:%s:%d\n", r.GetLabelFQDN(), escapeString(r.GetTargetField()), r.TTL)
		}
	}
	return nil
}
