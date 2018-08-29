package geoip

import (
	"github.com/pkg/errors"

	"github.com/elastic/beats/libbeat/common"
)

// Config defines the configuration options for the geoip processor.
type Config struct {
	Database    string        `config:"database"`
	Fields      common.MapStr `config:"fields"`
	reverseFlat map[string]string
}

// Validate validates the data contained in the config.
func (c *Config) Validate() error {
	c.reverseFlat = map[string]string{}
	for k, v := range c.Fields.Flatten() {
		target, ok := v.(string)
		if !ok {
			return errors.Errorf("target field for geoip lookup of %v "+
				"must be a string but got %T", k, v)
		}
		c.reverseFlat[k] = target
	}

	return nil
}

var defaultConfig = Config{
	Database: "GeoLite2-City.mmdb",
	Fields: common.MapStr{
		"source.ip":      "source.geo",
		"destination.ip": "destination.geo",
	},
}
