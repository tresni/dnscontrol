package tinydns

/*

tinydns -
  Generate zonefiles suitiable for tinydns.  You will need to concat
  all zone files into a single 'data' file to use with tinydns.

	The zonefiles are read and written to the directory -tinydns_dir

	If the old zonefiles are readable, we read them to determine
	if an update is actually needed. The old zonefile is also used
	as the basis for generating the new SOA serial number.

*/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	//	"github.com/pkg/errors"

	"github.com/StackExchange/dnscontrol/models"
	"github.com/StackExchange/dnscontrol/providers"
	"github.com/StackExchange/dnscontrol/providers/bind"
	"github.com/StackExchange/dnscontrol/providers/diff"
)

var features = providers.DocumentationNotes{
	providers.CanUseCAA:        providers.Can(),
	providers.CanUsePTR:        providers.Can(),
	providers.CanUseNAPTR:      providers.Can(),
	providers.CanUseSRV:        providers.Can(),
	providers.CanUseSSHFP:      providers.Can(),
	providers.CanUseTLSA:       providers.Can(),
	providers.DocCreateDomains: providers.Can("Driver just maintains list of zone files. It should automatically add missing ones."),
	providers.DocDualHost:      providers.Can(),
}

func initTinydns(config map[string]string, providermeta json.RawMessage) (providers.DNSServiceProvider, error) {
	// config -- the key/values from creds.json
	// meta -- the json blob from NewReq('name', 'TYPE', meta)
	api := &Tinydns{
		directory: config["directory"],
	}
	if api.directory == "" {
		api.directory = "zones"
	}

	if len(providermeta) != 0 {
		err := json.Unmarshal(providermeta, api)
		if err != nil {
			return nil, err
		}
	}
	//api.nameservers = models.StringsToNameservers(api.DefaultNS)
	return api, nil
}

func init() {
	providers.RegisterDomainServiceProviderType("TINYDNS", initTinydns, features)
}

type soaInfo struct {
	bind.SoaInfo
	TTL uint32 `json:"ttl"`
}

// Tinydns is the provider handle for the Tinydns driver.
type Tinydns struct {
	//DefaultNS   []string `json:"default_ns"`
	DefaultSoa soaInfo `json:"default_soa"`
	//nameservers []*models.Nameserver
	directory string
}

func makeDefaultSOA(info soaInfo, origin string) *models.RecordConfig {
	// Make a default SOA record in case one isn't found:
	soaRec := models.RecordConfig{
		Type: "SOA",
	}
	soaRec.SetLabel("@", origin)
	if len(info.Ns) == 0 {
		info.Ns = "DEFAULT_NOT_SET."
	}
	if len(info.Mbox) == 0 {
		info.Mbox = "DEFAULT_NOT_SET."
	}
	if info.Refresh == 0 {
		info.Refresh = 3600
	}
	if info.Retry == 0 {
		info.Retry = 600
	}
	if info.Expire == 0 {
		info.Expire = 604800
	}
	if info.Minttl == 0 {
		info.Minttl = 1440
	}
	soaRec.SetTarget(info.String())
	soaRec.TTL = info.TTL

	return &soaRec
}

// GetNameservers returns the nameservers for a domain.
func (c *Tinydns) GetNameservers(string) ([]*models.Nameserver, error) {
	return nil, nil
}

// GetDomainCorrections returns a list of corrections to update a domain.
func (c *Tinydns) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	dc.Punycode()
	// Phase 1: Copy everything to []*models.RecordConfig:
	//    expectedRecords < dc.Records[i]
	//    foundRecords < zonefile
	//
	// Phase 2: Do any manipulations:
	// add NS
	// manipulate SOA
	//
	// Phase 3: Convert to []diff.Records and compare:
	// expectedDiffRecords < expectedRecords
	// foundDiffRecords < foundRecords
	// diff.Inc...(foundDiffRecords, expectedDiffRecords )

	// Default SOA record.  If we see one in the zone, this will be replaced.
	soaRec := makeDefaultSOA(c.DefaultSoa, dc.Name)

	// Read foundRecords:
	foundRecords := make([]*models.RecordConfig, 0)
	//var oldSerial, newSerial uint32

	if _, err := os.Stat(c.directory); os.IsNotExist(err) {
		fmt.Printf("\nWARNING: Tinydns directory %q does not exist!\n", c.directory)
	}

	zonefile := filepath.Join(c.directory, strings.Replace(strings.ToLower(dc.Name), "/", "_", -1)+".data")
	foundFH, err := os.Open(zonefile)
	zoneFileFound := err == nil
	if err != nil && !os.IsNotExist(os.ErrNotExist) {
		// Don't whine if the file doesn't exist. However all other
		// errors will be reported.
		fmt.Printf("\nCould not read zonefile: %v\n", err)
	} else {
		for _, r := range ReadDataFile(dc.Name, foundFH) {
			var rec models.RecordConfig
			rec, _ = bind.RrToRecord(r, dc.Name, 0)
			foundRecords = append(foundRecords, &rec)
		}
	}

	// Add SOA record to expected set:
	if !dc.HasRecordTypeName("SOA", "@") {
		dc.Records = append(models.Records{soaRec}, dc.Records...)
	}

	// Normalize
	models.PostProcessRecords(foundRecords)

	differ := diff.New(dc)
	_, create, del, mod := differ.IncrementalDiff(foundRecords)

	buf := &bytes.Buffer{}
	// Print a list of changes. Generate an actual change that is the zone
	changes := false
	for _, i := range create {
		changes = true
		if zoneFileFound {
			fmt.Fprintln(buf, i)
		}
	}
	for _, i := range del {
		changes = true
		if zoneFileFound {
			fmt.Fprintln(buf, i)
		}
	}
	for _, i := range mod {
		changes = true
		if zoneFileFound {
			fmt.Fprintln(buf, i)
		}
	}
	msg := fmt.Sprintf("GENERATE_ZONEFILE: %s\n", dc.Name)
	if !zoneFileFound {
		msg = msg + fmt.Sprintf(" (%d records)\n", len(create))
	}
	msg += buf.String()
	corrections := []*models.Correction{}
	if changes {
		corrections = append(corrections,
			&models.Correction{
				Msg: msg,
				F: func() error {
					fmt.Printf("CREATING ZONEFILE: %v\n", zonefile)
					zf, err := os.Create(zonefile)
					if err != nil {
						log.Fatalf("Could not create zonefile: %v", err)
					}
					err = WriteDataFile(zf, dc.Records, dc.Name)

					if err != nil {
						log.Fatalf("WriteZoneFile error: %v\n", err)
					}
					err = zf.Close()
					if err != nil {
						log.Fatalf("Closing: %v", err)
					}
					return nil
				},
			})
	}

	return corrections, nil
}
