package notify

import (
	"context"
	"encoding/json"
)

func init() { Backends.Register("pagerduty", pagerdutyBackend{}) }

// pagerdutyBackend triggers a PagerDuty Events API v2 incident. It exists to
// prove the seam generalises past a single {url} field: its config is a secret
// routing key plus a severity, and it only fires on terminal states. Adding it
// was one file — no edits to the consumer, the create handler, or the schema.
type pagerdutyBackend struct{}

func (pagerdutyBackend) Type() string { return "pagerduty" }

func (pagerdutyBackend) ConfigFields() []Field {
	return []Field{
		{ID: "routing_key", Label: "Integration Routing Key", Type: "password", Secret: true},
		{ID: "severity", Label: "Severity", Type: "text", Default: "error"},
	}
}

func (pagerdutyBackend) Send(ctx context.Context, cfg map[string]string, msg Message) error {
	if msg.Event == "started" {
		return nil // only page on terminal states
	}
	body, _ := json.Marshal(map[string]interface{}{
		"routing_key":  cfg["routing_key"],
		"event_action": "trigger",
		"payload": map[string]string{
			"summary":  "Praetor " + msg.Subject() + " \"" + msg.JobName + "\" " + msg.Status,
			"source":   "praetor",
			"severity": cfg["severity"],
		},
	})
	return postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", body)
}
