package axfr

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/miekg/dns/dnsutil"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
	"github.com/StackExchange/dnscontrol/providers/diff"
	"github.com/miekg/dns"
)

type axfr struct {
	Server      string
	Nameservers []string
}

func init() {
	providers.RegisterDomainServiceProviderType("AXFR", New)
}

func New(config map[string]string, _ json.RawMessage) (models.DNSServiceProviderDriver, error) {
	a := &axfr{Server: config["server"]}
	if a.Server == "" {
		return nil, fmt.Errorf("AXFR driver requires 'server' parameter")
	}
	return a, nil
}

func (a *axfr) GetNameservers(domain string) ([]*models.Nameserver, error) {
	// TODO: allow configuration via creds or metadata
	return models.StringsToNameservers([]string{a.Server}), nil
}

func (a *axfr) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	dc.Punycode()
	recs, err := a.getRecords(dc.Name)
	if err != nil {
		return nil, err
	}
	dc.Filter(func(r *models.RecordConfig) bool {
		return r.Type != "NS"
	})
	differ := diff.New(dc)
	changes := differ.ChangedGroups(recs)
	if len(changes) == 0 {
		return nil, nil
	}

	msg := &dns.Msg{}
	msg.SetUpdate(dc.Name + ".")
	correction := &models.Correction{
		F: func() error {
			cli := dns.Client{
				Timeout: 15 * time.Minute,
			}
			m, rtt, err := cli.Exchange(msg, a.Server+":53")
			if err != nil {
				return err
			}
			if m.Rcode != dns.RcodeSuccess {
				return fmt.Errorf("Dynamic update failed. Response code: %s", dns.RcodeToString[m.Rcode])
			}
			fmt.Println(rtt)
			return nil
		},
	}
	groupedRecs := dc.Records.Grouped()
	for key, texts := range changes {
		for _, txt := range texts {
			correction.Msg += txt + "\n"
		}
		// always delete whole set
		deleteRRSet(msg, dc.Name, key)
	}
	for key := range changes {
		if recs := groupedRecs[key]; recs != nil {
			rrs := make([]dns.RR, len(recs))
			for i, rec := range recs {
				rrs[i] = rec.ToRR()
			}
			msg.Insert(rrs)
		}
	}

	return []*models.Correction{correction}, nil
}

func deleteRRSet(msg *dns.Msg, origin string, key models.RecordKey) {
	// from rfc2136 Section 2.5.2
	// One RR is added to the Update Section whose NAME and TYPE are those
	// of the RRset to be deleted.  TTL must be specified as zero (0) and is
	// otherwise not used by the primary master.  CLASS must be specified as
	// ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
	// If no such RRset exists, then this Update RR will be silently ignored
	// by the primary master.
	header := &dns.RR_Header{
		Class:    dns.ClassANY,
		Name:     dnsutil.AddOrigin(key.Name, origin+"."),
		Rdlength: 0,
		Rrtype:   dns.StringToType[key.Type],
		Ttl:      0,
	}
	msg.Ns = append(msg.Ns, header)
}

func (a *axfr) getRecords(domain string) (models.Records, error) {
	msg := &dns.Msg{}
	msg.SetAxfr(domain + ".")
	transfer := &dns.Transfer{}
	envs, err := transfer.In(msg, a.Server+":53")
	if err != nil {
		return nil, err
	}
	var recs models.Records
	for env := range envs {
		if env.Error != nil {
			return nil, env.Error
		}
		for _, rr := range env.RR {
			if rr.Header().Rrtype == dns.TypeSOA || rr.Header().Rrtype == dns.TypeNS {
				continue
			}
			recs = append(recs, models.RRToRecord(rr, domain))
		}
	}
	return recs, nil
}
