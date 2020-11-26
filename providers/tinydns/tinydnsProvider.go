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

	//	"strings"

	//	"github.com/pkg/errors"

	"github.com/StackExchange/dnscontrol/v3/models"
	"github.com/StackExchange/dnscontrol/v3/pkg/diff"
	"github.com/StackExchange/dnscontrol/v3/providers"
	"github.com/StackExchange/dnscontrol/v3/providers/bind"
	"github.com/miekg/dns/dnsutil"
)

var features = providers.DocumentationNotes{
	providers.CanUseCAA:        providers.Can(),
	providers.CanUsePTR:        providers.Can(),
	providers.CanUseNAPTR:      providers.Can(),
	providers.CanUseSRV:        providers.Can(),
	providers.CanUseSSHFP:      providers.Can(),
	providers.CanUseTLSA:       providers.Can(),
	providers.CanUseTXTMulti:   providers.Can(),
	providers.DocCreateDomains: providers.Can("Driver just maintains list of zone files. It should automatically add missing ones."),
	providers.DocDualHost:      providers.Can(),
	providers.CanGetZones:      providers.Can(),
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
	err := api.readDataFile()
	if err != nil {
		return nil, err
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

// Tinydns is the provider handle for the Tinydns driver.
type Tinydns struct {
	//DefaultNS   []string `json:"default_ns"`
	DefaultSoa bind.SoaInfo `json:"default_soa"`
	//nameservers []*models.Nameserver
	directory      string
	zones          ZoneData
	dataFileExists bool
}

func makeDefaultSOA(info bind.SoaInfo, origin string) *models.RecordConfig {
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
	soaRec.SetTargetSOA(
		info.Ns,
		info.Mbox,
		info.Serial,
		info.Refresh,
		info.Retry,
		info.Expire,
		info.Minttl)
	soaRec.TTL = info.TTL

	return &soaRec
}

// GetNameservers returns the nameservers for a domain.
func (c *Tinydns) GetNameservers(string) ([]*models.Nameserver, error) {
	return nil, nil
}

func (c *Tinydns) readDataFile() error {
	if _, err := os.Stat(c.directory); os.IsNotExist(err) {
		fmt.Printf("\nWARNING: Tinydns directory %q does not exist!\n", c.directory)
	}

	zonefile := filepath.Join(c.directory, "data")
	foundFH, err := os.Open(zonefile)
	if err != nil && !os.IsNotExist(err) {
		// Don't whine if the file doesn't exist. However all other
		// errors will be reported.
		fmt.Printf("\nCould not read zonefile: %v\n", err)
		return err
	}
	c.zones = ReadDataFile(foundFH)
	c.dataFileExists = err == nil
	return nil
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (c *Tinydns) GetZoneRecords(domain string) (models.Records, error) {
	return c.getZoneRecords(domain)
}

func (c *Tinydns) getZoneRecords(domain string) (models.Records, error) {
	// Read foundRecords:
	foundRecords := make([]*models.RecordConfig, 0)

	fz := FindZone(&c.zones, domain)
	records := fz.Records
	if fz.soa != nil {
		records = append(records, fz.soa)
	}
	for _, r := range records {
		rec := models.RRtoRC(r, domain)
		foundRecords = append(foundRecords, &rec)
	}

	return foundRecords, nil
}

// GetDomainCorrections returns a list of corrections to update a domain.
func (c *Tinydns) GetDomainCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	dc.Punycode()
	// Default SOA record.  If we see one in the zone, this will be replaced.
	soaRec := makeDefaultSOA(c.DefaultSoa, dc.Name)

	zones, zoneFileFound := c.zones, c.dataFileExists

	foundRecords, err := c.GetZoneRecords(dc.Name)
	if err != nil {
		return nil, err
	}

	// Add SOA record to expected set:
	if !dc.Records.HasRecordTypeName("SOA", "@") {
		dc.Records = append(models.Records{soaRec}, dc.Records...)
	}

	models.PostProcessRecords(foundRecords)

	differ := diff.New(dc)
	_, create, del, mod, err := differ.IncrementalDiff(foundRecords)
	if err != nil {
		return nil, err
	}

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
		msg += fmt.Sprintf(" (%d records)\n", len(create))
	}
	msg += buf.String()
	corrections := []*models.Correction{}

	/* Grab all records from all zones EXCEPT the zone we care about */
	records := ZonesToRecordConfigs(&zones, dc.Name)
	models.PostProcessRecords(records)
	/* Swap out dc.Records with the full dataset */
	dc.Records = append(records, dc.Records...)
	/* Now write out the data file */
	if changes {
		corrections = append(corrections,
			&models.Correction{
				Msg: msg,
				F: func() error {
					zonefile := filepath.Join(c.directory, "data")
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

func (c *Tinydns) recursiveListZones(zone *ZoneData, parent string, r chan string) {
	name := dnsutil.AddOrigin(zone.name, parent)
	if zone.soa != nil {
		r <- name
	}
	for z := range zone.children {
		c.recursiveListZones(zone.children[z], name, r)
	}
}

func (c *Tinydns) listZones(r chan string) {
	c.recursiveListZones(&c.zones, "", r)
	close(r)
}

// ListZones lists zones
func (c *Tinydns) ListZones() ([]string, error) {
	if !c.dataFileExists {
		return nil, nil
	}
	r := make(chan string)
	var zones []string

	go c.listZones(r)

	for zone := range r {
		zones = append(zones, zone)
	}

	return zones, nil
}
