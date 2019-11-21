package tinydns

import (
	"testing"

	"github.com/miekg/dns"
)

func TestFindLabel(t *testing.T) {
	com := ZoneData{name: "com"}
	other := ZoneData{name: "another"}
	zd := ZoneData{children: []*ZoneData{&com, &other}}

	if findLabel(&zd, "com") != &com {
		t.Error("Did not find label")
	}

	if findLabel(&zd, "none") != nil {
		t.Error("Found non existent label")
	}
}

func TestFindZone(t *testing.T) {
	other := ZoneData{name: "another", soa: &dns.SOA{}}
	com := ZoneData{name: "com", children: []*ZoneData{&other}, soa: &dns.SOA{}}
	zd := ZoneData{children: []*ZoneData{&com}}

	if FindZone(&zd, "another.com") != &other {
		t.Error("Did not find another.com")
	}

	if FindZone(&zd, "this.com") != &com {
		t.Error("This should return com")
	}

	if FindZone(&zd, "root.please") != &zd {
		t.Error("We should get the root Zone Data")
	}
}

func TestAddZone(t *testing.T) {
	var z ZoneData
	zones := []string{
		"this.is.a.long.label",
		"opendns.com",
		"thor.opendns.com",
	}

	for _, zone := range zones {
		r := new(dns.SOA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600}
		addZone(&z, r)
	}
	zone := FindZone(&z, "this.is.a.long.label")
	if zone.name != "this" {
		t.Error("We didn't get the right zone back!")
	}

	zone = FindZone(&z, "thor.opendns.com")
	if zone.name != "thor" {
		t.Errorf("We didn't get thor back: %s", zone.name)
	}
}
