package tinydns

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/StackExchange/dnscontrol/v3/models"

	//"github.com/StackExchange/dnscontrol/providers/bind"
	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
	//"github.com/miekg/dns/dnsutil"
)

// ReadError is an error reading the tinydns data file
type ReadError struct {
	err string
}

func (e *ReadError) Error() (s string) {
	s += e.err
	return
}

// ZoneData is the holder for records for each SOA
type ZoneData struct {
	name     string
	Records  []dns.RR
	children []*ZoneData
	soa      dns.RR
}

func parseDataFile(r io.Reader, rrs chan dns.RR) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if err := lineToRecord(scanner.Text(), rrs); err != nil {
			log.Fatalf(err.Error())
		}
	}
	close(rrs)
}

// FindZone finds a zone by name in a ZoneData structure
func FindZone(z *ZoneData, name string) *ZoneData {
	labels := dns.SplitDomainName(name)
	soa, c := z, z
	for i := len(labels) - 1; i >= 0 && c != nil; i-- {
		c = findLabel(c, labels[i])
		if c == nil {
			return soa
		}
		if c.soa != nil {
			soa = c
		}
	}
	return soa
}

func findLabel(z *ZoneData, label string) *ZoneData {
	for _, c := range z.children {
		if c.name == label {
			return c
		}
	}
	return nil
}

func addZone(z *ZoneData, rr dns.RR) {
	labels := dns.SplitDomainName(rr.Header().Name)
	target := z
	for i := len(labels) - 1; i >= 0; i-- {
		c := findLabel(target, labels[i])
		if c == nil {
			c = &ZoneData{name: labels[i]}
			target.children = append(target.children, c)
		}
		target = c
	}
	target.soa = rr
}

func splitRecords(zone *ZoneData, rrs []dns.RR) ZoneData {
	for _, r := range rrs {
		z := FindZone(zone, r.Header().Name)
		z.Records = append(z.Records, r)
	}
	return *zone
}

func recurseZoneToRecords(zone *ZoneData, ignore, origin string, r chan *models.RecordConfig) {
	if zone.soa != nil {
		rec := models.RRtoRC(zone.soa, origin)
		r <- &rec
	}
	for _, rr := range zone.Records {
		if origin == "" {
			log.Printf("Skipping record outside an SOA: %q", rr)
			continue
		}
		rec := models.RRtoRC(rr, origin)
		r <- &rec
	}
	for _, c := range zone.children {
		recurseZoneToRecords(c, ignore, dnsutil.AddOrigin(zone.name, origin), r)
	}
}

func zoneToRecords(zone *ZoneData, ignore string, r chan *models.RecordConfig) {
	recurseZoneToRecords(zone, ignore, "", r)
	close(r)
}

// ZonesToRecordConfigs converts ZoneData to dnscontrol RecordConfig
func ZonesToRecordConfigs(zone *ZoneData, ignore string) []*models.RecordConfig {
	r := make(chan *models.RecordConfig)
	go zoneToRecords(zone, ignore, r)
	var recs []*models.RecordConfig
	for rr := range r {
		recs = append(recs, rr)
	}
	return recs
}

// ReadDataFile reads a tinydns data file and returns an array of zones & records
func ReadDataFile(r io.Reader) ZoneData {
	var foundRecords []dns.RR
	rrs := make(chan dns.RR)
	var zones ZoneData

	go parseDataFile(r, rrs)

	for rec := range rrs {
		switch rec.(type) {
		case *dns.SOA:
			addZone(&zones, rec)
		default:
			foundRecords = append(foundRecords, rec)
		}
	}

	return splitRecords(&zones, foundRecords)
}

func createARecord(fqdn, ip string, ttl uint32) dns.RR {
	r := new(dns.A)
	r.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
	r.A = net.ParseIP(strings.TrimSpace(ip))
	return r
}

func createNSRecord(fqdn, nameserver string, ttl uint32) dns.RR {
	r := new(dns.NS)
	r.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = dnsutil.AddOrigin(nameserver, ".")
	return r
}

func createSOARecord(fqdn, nameserver, mbox string, ttl uint32) dns.RR {
	r := new(dns.SOA)
	r.Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}
	r.Ns = nameserver
	r.Mbox = mbox
	return r
}

func lineToRecord(line string, rrs chan dns.RR) error {
	var r dns.RR

	if len(line) == 0 {
		return nil
	}
	fields := strings.Split(line[1:], ":")
	fqdn := fields[0]
	maxField := len(fields) - 1
	ttlField := maxField

	switch line[0] {
	case '.':
		// fqdn:ip:x:ttl:timestamp:lo
		nameserver := parseTinydnsName(fqdn, fields[2], "ns")
		ttl := parseTTL(fields[3])

		if len(fields[1]) != 0 && dns.IsSubDomain(fqdn, nameserver) {
			rrs <- createARecord(nameserver, fields[1], ttl)
		}
		rrs <- createSOARecord(fqdn, nameserver, "hostmaster."+fqdn, ttl)
		rrs <- createNSRecord(fqdn, nameserver, ttl)
		ttlField = 3
	case 'Z':
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
		r.(*dns.CNAME).Target = dnsutil.AddOrigin(fields[1], ".")
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
		r.(*dns.MX).Mx = dnsutil.AddOrigin(mx, ".")
		rrs <- r
	case '^':
		r = new(dns.PTR)
		ttl := parseTTL(fields[2])
		r.(*dns.PTR).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.(*dns.PTR).Ptr = dnsutil.AddOrigin(fields[1], ".")
		rrs <- r
		ttlField = 2
	case '\'':
		r = new(dns.TXT)
		ttl := parseTTL(fields[2])
		r.(*dns.TXT).Hdr = dns.RR_Header{Name: fqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
		data := string(deOctalString(fields[1]))
		// TODO: tinydns autosplits at 255, so we should do that on import to represent the same behavior
		// People should use AUTOSPLIT in their *.js files as tiny doesn't give the ability to split the
		// string arbitraially
		r.(*dns.TXT).Txt = []string{data}
		rrs <- r
		ttlField = 2
	case '&':
		ttl := parseTTL(fields[3])
		nameserver := parseTinydnsName(fqdn, fields[2], "ns")
		if len(fields[1]) != 0 && dns.IsSubDomain(fqdn, nameserver) {
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
			parts := strings.Fields(r.GetTargetCombined())
			if parts[2] == "0" {
				parts[2] = ""
			}
			fmt.Fprintf(w, "Z%s:%s:%d\n", r.GetLabelFQDN(), strings.Join(parts, ":"), r.TTL)
		case "A":
			//+fqdn:ip:ttl:timestamp:lo
			fmt.Fprintf(w, "+%s:%s:%d\n", r.GetLabelFQDN(), r.GetTargetField(), r.TTL)
		case "AAAA":
			fmt.Fprintf(w, ":%s:28:%s:%d\n", r.GetLabelFQDN(), octalBuf(r.GetTargetIP()), r.TTL)
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
			fmt.Fprintf(w, ":%s:44:\\%03o\\%03o%s:%d\n", r.GetLabelFQDN(), r.SshfpAlgorithm, r.SshfpFingerprint, octalBuf(hex), r.TTL)
		case "TLSA":
			fmt.Fprintf(w, ":%s:52:\\%03o\\%03o\\%03o%s:%d\n", r.GetLabelFQDN(), r.TlsaUsage, r.TlsaSelector, r.TlsaMatchingType, r.GetTargetField(), r.TTL)
		case "TXT":
			//'fqdn:s:ttl:timestamp:lo
			//You may use octal \nnn codes to include arbitrary bytes inside s; for example, \072 is a colon.
			//We can write multiple records, but we can't read them as tiny doesn't differentiate
			fmt.Fprintf(w, "'%s:%s:%d\n", r.GetLabelFQDN(), octalString(escapeString(r.GetTargetField())), r.TTL)
		}
	}
	return nil
}
