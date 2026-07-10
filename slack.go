package notify

import (
	"context"
	"encoding/json"
	"fmt"
)

func init() { Backends.Register("slack", slackBackend{}) }

// slackBackend posts a one-line message to a Slack incoming-webhook URL. The
// payload matches the pre-registry notifier.
type slackBackend struct{}

func (slackBackend) Type() string { return "slack" }

func (slackBackend) ConfigFields() []Field {
	return []Field{{ID: "url", Label: "Webhook URL", Type: "text", Secret: true}}
}

func (slackBackend) Send(ctx context.Context, cfg map[string]string, msg Message) error {
	body, _ := json.Marshal(map[string]string{
		"text": fmt.Sprintf("Praetor %s %q %s", msg.Subject(), msg.JobName, msg.Status),
	})
	return postJSON(ctx, cfg["url"], body)
}
