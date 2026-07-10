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
	payload := map[string]interface{}{
		"job_id": msg.JobID, "job_name": msg.JobName, "event": msg.Event, "status": msg.Status,
	}
	// A workflow message adds "kind"; a job message omits it, so its body stays
	// byte-for-byte the shape the pre-registry notifier sent.
	if msg.Kind != "" {
		payload["kind"] = msg.Kind
	}
	body, _ := json.Marshal(payload)
	return postJSON(ctx, cfg["url"], body)
}
