package asn

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
	"github.com/pkg/errors"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/paths"
	"github.com/elastic/beats/libbeat/processors"
)

const logName = "processor.asn"

func init() {
	processors.RegisterPlugin("asn", newASNProcessor)
}

type processor struct {
	Config
	db  *geoip2.Reader
	log *logp.Logger
}

func newASNProcessor(cfg *common.Config) (processors.Processor, error) {
	c := defaultConfig
	if err := cfg.Unpack(&c); err != nil {
		return nil, errors.Wrap(err, "fail to unpack the ASN configuration")
	}

	c.Database = paths.Resolve(paths.Home, c.Database)
	db, err := geoip2.Open(c.Database)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read ASN DB from %v", c.Database)
	}
	log := logp.NewLogger(logName)
	log.Infof("Loaded ASN database. type=%v", db.Metadata().DatabaseType)

	return &processor{
		Config: c,
		db:     db,
		log:    log,
	}, nil
}

func (p *processor) Close() error {
	return p.db.Close()
}

func (p *processor) String() string {
	return fmt.Sprintf("asn=[database=%s, fields=%v]", p.Config.Database, p.reverseFlat)
}

func (p *processor) Run(event *beat.Event) (*beat.Event, error) {
	for field, target := range p.Config.reverseFlat {
		v, err := event.GetValue(field)
		if err != nil {
			continue
		}

		ipStr, ok := v.(string)
		if !ok {
			continue
		}

		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// This returns a pointer to a zero-value geoip2.City when a lookup
		// finds nothing so we need to validate it.
		as, err := p.db.ASN(ip)
		if err != nil || as == nil || as.AutonomousSystemNumber == 0 {
			continue
		}

		m := common.MapStr{
			"org": as.AutonomousSystemOrganization,
			"num": as.AutonomousSystemNumber,
		}

		event.PutValue(target, m)
	}

	return event, nil
}
