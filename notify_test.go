package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// captureBody spins up a server that records the last request body, and points
// the given field's value at it.
func captureServer(t *testing.T) (targetURL string, last *[]byte) {
	t.Helper()
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRAETOR_NOTIFICATION_ALLOWED_HOSTS", parsed.Hostname())
	return srv.URL, &body
}

// TestWebhookPayloadUnchanged pins the exact JSON the webhook backend sends,
// which must match the pre-registry notifier byte-for-byte.
func TestWebhookPayloadUnchanged(t *testing.T) {
	url, last := captureServer(t)
	b, _ := Backends.Get("webhook")
	msg := Message{JobID: 7, JobName: "deploy", Event: "error", Status: "failed"}
	if err := b.Send(context.Background(), map[string]string{"url": url}, msg); err != nil {
		t.Fatal(err)
	}
	want := `{"event":"error","job_id":7,"job_name":"deploy","status":"failed"}`
	if string(*last) != want {
		t.Errorf("webhook body drifted:\n got: %s\nwant: %s", *last, want)
	}
}

func TestSlackPayloadUnchanged(t *testing.T) {
	url, last := captureServer(t)
	b, _ := Backends.Get("slack")
	msg := Message{JobID: 7, JobName: "deploy", Event: "success", Status: "succeeded"}
	if err := b.Send(context.Background(), map[string]string{"url": url}, msg); err != nil {
		t.Fatal(err)
	}
	want := `{"text":"Praetor job \"deploy\" succeeded"}`
	if string(*last) != want {
		t.Errorf("slack body drifted:\n got: %s\nwant: %s", *last, want)
	}
}

// TestWorkflowMessageWire proves a workflow message (Kind set) adds "kind" to the
// webhook body and names the subject in the slack text, while a job message's wire
// shape stays byte-identical (Kind omitted). Guards the additive Message change.
func TestWorkflowMessageWire(t *testing.T) {
	msg := Message{JobID: 12, JobName: "nightly", Event: "error", Status: "failed", Kind: "workflow"}

	url, last := captureServer(t)
	wb, _ := Backends.Get("webhook")
	if err := wb.Send(context.Background(), map[string]string{"url": url}, msg); err != nil {
		t.Fatal(err)
	}
	want := `{"event":"error","job_id":12,"job_name":"nightly","kind":"workflow","status":"failed"}`
	if string(*last) != want {
		t.Errorf("workflow webhook body:\n got: %s\nwant: %s", *last, want)
	}

	url2, last2 := captureServer(t)
	sb, _ := Backends.Get("slack")
	if err := sb.Send(context.Background(), map[string]string{"url": url2}, msg); err != nil {
		t.Fatal(err)
	}
	wantSlack := `{"text":"Praetor workflow \"nightly\" failed"}`
	if string(*last2) != wantSlack {
		t.Errorf("workflow slack body:\n got: %s\nwant: %s", *last2, wantSlack)
	}

	// A job message (no Kind) must still read "job" and omit the kind key.
	if got := (Message{JobName: "x", Status: "succeeded"}).Subject(); got != "job" {
		t.Errorf("job Subject() = %q, want job", got)
	}
}

// TestConfigRoundTrip proves a Secret field survives encrypt→store→decrypt and
// that non-secret defaults fill in.
func TestConfigRoundTrip(t *testing.T) {
	t.Setenv("PRAETOR_ALLOW_INSECURE_DEFAULTS", "true")
	b, _ := Backends.Get("pagerduty")
	raw, err := EncryptConfig(b, map[string]string{"routing_key": "R123"})
	if err != nil {
		t.Fatal(err)
	}
	// The routing key must not be stored in cleartext.
	var stored map[string]string
	_ = json.Unmarshal(raw, &stored)
	if stored["routing_key"] == "R123" {
		t.Errorf("routing_key stored in cleartext")
	}
	if stored["severity"] != "error" {
		t.Errorf("severity default not applied: %q", stored["severity"])
	}
	got, err := DecryptConfig(b, raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"routing_key": "R123", "severity": "error"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip = %v want %v", got, want)
	}
}

func TestEncryptConfigRejectsUnknownField(t *testing.T) {
	t.Setenv("PRAETOR_ALLOW_INSECURE_DEFAULTS", "true")
	b, _ := Backends.Get("slack")
	if _, err := EncryptConfig(b, map[string]string{"url": "https://x", "bogus": "y"}); err == nil {
		t.Errorf("expected error for unknown field")
	}
}

func TestAllBackendsRegistered(t *testing.T) {
	got := Backends.Names()
	want := []string{"pagerduty", "slack", "webhook"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("registered backends = %v want %v", got, want)
	}
}

func TestValidateDestinationRejectsUnsafeTargets(t *testing.T) {
	t.Setenv("PRAETOR_NOTIFICATION_ALLOWED_HOSTS", "")
	for _, raw := range []string{
		"http://example.com/hook",
		"file:///etc/passwd",
		"https:///missing-host",
		"https://user:secret@example.com/hook",
		"https://127.0.0.1/hook",
		"https://localhost/hook",
		"https://169.254.169.254/latest/meta-data",
	} {
		t.Run(raw, func(t *testing.T) {
			if err := ValidateDestination(context.Background(), raw); err == nil {
				t.Fatalf("ValidateDestination(%q) accepted an unsafe target", raw)
			}
		})
	}
}

func TestAllowlistedDestinationMayUseHTTPAndPrivateAddress(t *testing.T) {
	url, _ := captureServer(t)
	if err := ValidateDestination(context.Background(), url); err != nil {
		t.Fatalf("allowlisted destination rejected: %v", err)
	}
}

func TestNotificationDeliveryDoesNotFollowRedirects(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(destination.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)
	redirectURL, _ := url.Parse(redirect.URL)
	destinationURL, _ := url.Parse(destination.URL)
	t.Setenv("PRAETOR_NOTIFICATION_ALLOWED_HOSTS", redirectURL.Hostname()+","+destinationURL.Hostname())

	b, _ := Backends.Get("webhook")
	err := b.Send(context.Background(), map[string]string{"url": redirect.URL}, Message{JobID: 9, JobName: "redirect"})
	if err == nil || !strings.Contains(err.Error(), "returned 302") {
		t.Fatalf("redirect delivery error = %v, want returned 302", err)
	}
	if got := destinationCalls.Load(); got != 0 {
		t.Fatalf("redirect destination received %d request(s), want 0", got)
	}
}

func TestNotificationDeliveryRejectsNonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)
	parsed, _ := url.Parse(server.URL)
	t.Setenv("PRAETOR_NOTIFICATION_ALLOWED_HOSTS", parsed.Hostname())
	b, _ := Backends.Get("slack")
	err := b.Send(context.Background(), map[string]string{"url": server.URL}, Message{JobName: "failure"})
	if err == nil || !strings.Contains(err.Error(), "returned 502") {
		t.Fatalf("delivery error = %v, want returned 502", err)
	}
}
