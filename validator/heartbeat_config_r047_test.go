package main

import (
	"testing"

	"github.com/ptudor/sigillum-dnssec/validator/internal/config"
)

// R-047: an enabled heartbeat with missing credentials or a non-HTTPS URL must
// fail configuration validation rather than silently disabling monitoring or
// leaking the API key over cleartext.
func TestR047_HeartbeatValidation(t *testing.T) {
	base := func() *config.Config {
		c := config.DefaultConfig()
		c.HeartbeatEnabled = true
		c.HeartbeatURL = "https://mon.invalid/heartbeat/"
		c.HeartbeatAPIKey = "k"
		c.HeartbeatApp = "app"
		return c
	}

	// A fully-specified HTTPS heartbeat validates.
	if err := base().Validate(); err != nil {
		t.Fatalf("valid heartbeat config should pass: %v", err)
	}

	cases := map[string]func(*config.Config){
		"missing api_key": func(c *config.Config) { c.HeartbeatAPIKey = "" },
		"missing app":     func(c *config.Config) { c.HeartbeatApp = "" },
		"missing url":     func(c *config.Config) { c.HeartbeatURL = "" },
		"http url":        func(c *config.Config) { c.HeartbeatURL = "http://mon.invalid/heartbeat/" },
	}
	for name, mut := range cases {
		c := base()
		mut(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: enabled heartbeat must fail validation", name)
		}
	}

	// Disabled heartbeat with incomplete config must NOT fail (disabled-by-default).
	c := config.DefaultConfig()
	c.HeartbeatEnabled = false
	c.HeartbeatAPIKey = ""
	c.HeartbeatURL = ""
	if err := c.Validate(); err != nil {
		t.Errorf("disabled incomplete heartbeat must not fail validation: %v", err)
	}
}
