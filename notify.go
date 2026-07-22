// Package notify is the pluggable notification-backend seam.
//
// A notification backend delivers a job-lifecycle message to some external
// system (a webhook, Slack, PagerDuty, ...). Each backend is one self-registering
// file: it declares its config schema (ConfigFields) and how to Send. The API
// renders its create-form and validates/encrypts config from that schema, and
// the consumer dispatches through the registry with no per-type switch. Adding a
// backend is therefore a single new file — no edits to the consumer, the create
// handler, or the schema.
//
// See docs/modularity-plugin-architecture.md (§C) and the B3 backlog item.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/praetordev/crypto"
	"github.com/praetordev/registry"
)

// Message is the backend-agnostic notification content a producer builds when a
// subject (a job, or a workflow run) reaches a lifecycle event. JobID/JobName are
// the subject's id and display name — for a workflow they are the workflow_job id
// and the workflow name (the field names are historical; Kind disambiguates).
type Message struct {
	JobID   int64  `json:"job_id"`
	JobName string `json:"job_name"`
	Event   string `json:"event"`  // success | error | started | approval
	Status  string `json:"status"` // human verb: succeeded | failed | needs approval
	// Kind names the subject for human-facing backends ("workflow", "workflow
	// approval"); empty means an ordinary job. It is omitempty so a job message's
	// wire shape stays byte-identical to the pre-workflow notifier.
	Kind string `json:"kind,omitempty"`
}

// Subject returns the human noun for the message's subject: Kind when set, else
// "job". Used by the text backends so a job reads "Praetor job ..." unchanged and
// a workflow reads "Praetor workflow ...".
func (m Message) Subject() string {
	if m.Kind != "" {
		return m.Kind
	}
	return "job"
}

// SendOne resolves the backend for a stored (notificationType, config) and
// delivers msg. It is the shared delivery primitive used by every producer (the
// consumer for jobs, the scheduler for workflows) so backend lookup, config
// decryption and Send live in exactly one place; callers own row iteration and
// logging. Returns a descriptive error; never panics on an unknown type.
func SendOne(ctx context.Context, notificationType string, config json.RawMessage, msg Message) error {
	b, ok := Backends.Get(notificationType)
	if !ok {
		return fmt.Errorf("unknown notification backend %q", notificationType)
	}
	cfg, err := DecryptConfig(b, config)
	if err != nil {
		return fmt.Errorf("decrypt config for %s: %w", notificationType, err)
	}
	return b.Send(ctx, cfg, msg)
}

// Field describes one config input. Its shape mirrors credential_types.inputs
// ({id,label,type,secret}) so the frontend renders both identically and the same
// encrypt/decrypt path applies. A Secret field is stored encrypted at rest.
type Field struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Type    string `json:"type"` // text | password | textarea
	Secret  bool   `json:"secret,omitempty"`
	Default string `json:"default,omitempty"`
}

// Backend delivers notifications for one notification_type.
type Backend interface {
	// Type is the notification_templates.notification_type discriminator.
	Type() string
	// ConfigFields is the backend's config schema: it drives the create-form,
	// validation, and which keys are encrypted at rest / decrypted before Send.
	ConfigFields() []Field
	// Send delivers msg using cfg. Secret fields arrive already decrypted.
	// Implementations must respect ctx (the consumer sends with a timeout).
	Send(ctx context.Context, cfg map[string]string, msg Message) error
}

// Backends is the process-wide backend registry. Backend files self-register in
// init(); importing pkg/notify pulls in all built-ins.
var Backends = registry.New[Backend]("notify backend")

// secretIDs returns the set of Secret field ids for a backend.
func secretIDs(b Backend) map[string]bool {
	s := map[string]bool{}
	for _, f := range b.ConfigFields() {
		if f.Secret {
			s[f.ID] = true
		}
	}
	return s
}

// EncryptConfig validates input against the backend's schema and returns the
// JSON stored in notification_templates.config, with Secret fields encrypted.
// Unknown keys are rejected; a missing non-Secret field falls back to its
// Default; a missing required (no-default) field is an error.
func EncryptConfig(b Backend, input map[string]string) (json.RawMessage, error) {
	known := map[string]Field{}
	for _, f := range b.ConfigFields() {
		known[f.ID] = f
	}
	for id := range input {
		if _, ok := known[id]; !ok {
			return nil, fmt.Errorf("unknown config field %q for %s", id, b.Type())
		}
	}
	out := map[string]string{}
	for id, f := range known {
		v, ok := input[id]
		if !ok || v == "" {
			if f.Default != "" {
				v = f.Default
			} else {
				return nil, fmt.Errorf("missing required config field %q for %s", id, b.Type())
			}
		}
		if f.Secret {
			enc, err := crypto.EncryptSecret(v)
			if err != nil {
				return nil, err
			}
			v = enc
		}
		out[id] = v
	}
	return json.Marshal(out)
}

// DecryptConfig unmarshals a stored config blob and decrypts its Secret fields,
// yielding the plaintext map handed to Send. A value that fails to decrypt is
// passed through as-is (tolerates legacy/unencrypted rows), matching the prior
// notifier's behaviour.
func DecryptConfig(b Backend, raw json.RawMessage) (map[string]string, error) {
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, err
	}
	secret := secretIDs(b)
	out := map[string]string{}
	for k, v := range stored {
		if secret[k] {
			if dec, err := crypto.DecryptSecret(v); err == nil {
				v = dec
			}
		}
		out[k] = v
	}
	return out, nil
}

// postJSON POSTs body as application/json to url, honouring ctx. Shared by the
// HTTP-shaped backends.
func postJSON(ctx context.Context, url string, body []byte) error {
	client, err := notificationHTTPClient(ctx, url)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req) // #nosec G704 -- destination and dial target are validated below.
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("notification endpoint returned %d", resp.StatusCode)
	}
	return nil
}

// ValidateDestination verifies an operator-supplied HTTP notification endpoint.
// Public destinations require HTTPS. Private, loopback, link-local, and plain
// HTTP destinations are accepted only when their exact hostname is present in
// PRAETOR_NOTIFICATION_ALLOWED_HOSTS. The same validation runs again when the
// transport dials, preventing a later DNS answer from widening the destination.
func ValidateDestination(ctx context.Context, raw string) error {
	_, _, err := validateDestination(ctx, raw)
	return err
}

func validateDestination(ctx context.Context, raw string) (*url.URL, bool, error) {
	destination, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, false, fmt.Errorf("parse notification destination: %w", err)
	}
	if destination.Hostname() == "" {
		return nil, false, fmt.Errorf("notification destination must include a host")
	}
	if destination.User != nil {
		return nil, false, fmt.Errorf("notification destination must not include user information")
	}
	host := strings.ToLower(strings.TrimSuffix(destination.Hostname(), "."))
	allowlisted := notificationAllowedHosts()[host]
	if destination.Scheme != "https" && !(allowlisted && destination.Scheme == "http") {
		return nil, false, fmt.Errorf("notification destination must use https unless its host is explicitly allowlisted")
	}
	if allowlisted {
		return destination, true, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return nil, false, fmt.Errorf("resolve notification destination: %w", err)
	}
	if len(addresses) == 0 {
		return nil, false, fmt.Errorf("notification destination did not resolve")
	}
	for _, address := range addresses {
		if !isPublicNotificationIP(address.IP) {
			return nil, false, fmt.Errorf("notification destination resolves to a non-public address")
		}
	}
	return destination, false, nil
}

func notificationAllowedHosts() map[string]bool {
	allowed := make(map[string]bool)
	for _, raw := range strings.Split(os.Getenv("PRAETOR_NOTIFICATION_ALLOWED_HOSTS"), ",") {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if host != "" {
			allowed[host] = true
		}
	}
	return allowed
}

func isPublicNotificationIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified()
}

func notificationHTTPClient(ctx context.Context, raw string) (*http.Client, error) {
	destination, allowlisted, err := validateDestination(ctx, raw)
	if err != nil {
		return nil, err
	}
	destinationHost := strings.ToLower(strings.TrimSuffix(destination.Hostname(), "."))
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("parse notification dial address: %w", err)
			}
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if host != destinationHost {
				return nil, fmt.Errorf("notification dial host does not match the validated destination")
			}
			if allowlisted {
				return dialer.DialContext(dialCtx, network, net.JoinHostPort(host, port))
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(dialCtx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve notification dial target: %w", err)
			}
			for _, candidate := range addresses {
				if !isPublicNotificationIP(candidate.IP) {
					return nil, fmt.Errorf("notification dial target resolved to a non-public address")
				}
			}
			if len(addresses) == 0 {
				return nil, fmt.Errorf("notification dial target did not resolve")
			}
			return dialer.DialContext(dialCtx, network, net.JoinHostPort(addresses[0].IP.String(), port))
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
