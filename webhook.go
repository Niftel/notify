package notify

import (
	"context"
	"encoding/json"
)

func init() { Backends.Register("webhook", webhookBackend{}) }

// webhookBackend POSTs a generic JSON body describing the job event. The body is
// byte-for-byte the shape the pre-registry notifier sent.
type webhookBackend struct{}

func (webhookBackend) Type() string { return "webhook" }

func (webhookBackend) ConfigFields() []Field {
	return []Field{{ID: "url", Label: "Target URL", Type: "text", Secret: true}}
}

func (webhookBackend) Send(ctx context.Context, cfg map[string]string, msg Message) error {
	body, _ := json.Marshal(map[string]interface{}{
		"job_id": msg.JobID, "job_name": msg.JobName, "event": msg.Event, "status": msg.Status,
	})
	return postJSON(ctx, cfg["url"], body)
}
