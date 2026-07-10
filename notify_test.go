package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// captureBody spins up a server that records the last request body, and points
// the given field's value at it.
func captureServer(t *testing.T) (url string, last *[]byte) {
	t.Helper()
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
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
