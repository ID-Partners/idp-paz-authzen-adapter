package main

// A lightweight in-memory feed of authorization decisions, exposed over
// Server-Sent Events so the demo UI can render a live "PDP decisions" sidebar.
// Every call to /access/v1/evaluation(s) records one event per decision. The
// feed is best-effort: a ring buffer of the most recent decisions plus a fan-out
// to connected SSE subscribers. It never blocks or fails the authorization path.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// pdpEvent is one authorization decision, shaped for the sidebar.
type pdpEvent struct {
	Ts       string            `json:"ts"`
	Seq      int64             `json:"seq"`
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Subject  string            `json:"subject"`
	Decision string            `json:"decision"` // PERMIT | DENY
	StepUp   bool              `json:"step_up,omitempty"`
	Scope    string            `json:"scope,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	// DecisionID + Raw come straight from PingAuthorize's governance-engine response
	// (the same record it writes to its policy-decision log) so the UI can show the
	// unedited product output and cross-reference it in `railway logs`.
	DecisionID string `json:"decision_id,omitempty"`
	Raw        string `json:"raw,omitempty"`
}

const feedRingSize = 200

type decisionFeed struct {
	mu   sync.Mutex
	seq  int64
	ring []pdpEvent
	subs map[chan pdpEvent]struct{}
}

var feed = &decisionFeed{subs: make(map[chan pdpEvent]struct{})}

// publish appends an event to the ring and fans it out to live subscribers.
// Slow subscribers are skipped (never block the PDP request path).
func (f *decisionFeed) publish(e pdpEvent) {
	f.mu.Lock()
	f.seq++
	e.Seq = f.seq
	f.ring = append(f.ring, e)
	if len(f.ring) > feedRingSize {
		f.ring = f.ring[len(f.ring)-feedRingSize:]
	}
	for ch := range f.subs {
		select {
		case ch <- e:
		default:
		}
	}
	f.mu.Unlock()
}

func (f *decisionFeed) snapshot() []pdpEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]pdpEvent, len(f.ring))
	copy(out, f.ring)
	return out
}

func (f *decisionFeed) subscribe() chan pdpEvent {
	ch := make(chan pdpEvent, 64)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.mu.Unlock()
	return ch
}

func (f *decisionFeed) unsubscribe(ch chan pdpEvent) {
	f.mu.Lock()
	delete(f.subs, ch)
	f.mu.Unlock()
}

// pdpEventFrom distils the built PDP payload + the decision into a sidebar event.
func pdpEventFrom(p *PdpPayload, resp EvaluationResponse) pdpEvent {
	attr := func(k string) string {
		if p == nil {
			return ""
		}
		if v, ok := p.Attributes[k]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	e := pdpEvent{
		Ts:       time.Now().UTC().Format(time.RFC3339Nano),
		Action:   attr("actionName"),
		Resource: attr("resourceType"),
		Subject:  attr("agentId"),
		Decision: "DENY",
	}
	if e.Resource == "" {
		e.Resource = attr("resourceId")
	}
	if resp.Decision {
		e.Decision = "PERMIT"
	}
	if resp.Context != nil {
		c := *resp.Context
		if v, ok := c["step_up_required"].(bool); ok {
			e.StepUp = v
		}
		if v, ok := c["step_up_scope"].(string); ok {
			e.Scope = v
		}
		if v, ok := c["reason"]; ok {
			e.Reason = fmt.Sprintf("%v", v)
		}
	}
	// Compact set of policy-relevant attributes for the sidebar detail row.
	attrs := map[string]string{}
	for _, k := range []string{"amount", "currency", "to_account", "user_scope",
		"consented_amount", "consented_creditor", "token_aud", "onBehalfOf", "agentType"} {
		if v := attr(k); v != "" {
			attrs[k] = v
		}
	}
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	// Attach the verbatim PingAuthorize decision record + its id (pretty-printed
	// so the panel renders it readably).
	if resp.RawPDP != "" {
		e.Raw = resp.RawPDP
		var rec struct {
			ID string `json:"id"`
		}
		if json.Unmarshal([]byte(resp.RawPDP), &rec) == nil {
			e.DecisionID = rec.ID
		}
		var pretty bytes.Buffer
		if json.Indent(&pretty, []byte(resp.RawPDP), "", "  ") == nil {
			e.Raw = pretty.String()
		}
	}
	return e
}

// handlePdpEvents streams decisions as SSE: it first replays the recent ring so a
// freshly-opened sidebar isn't empty, then pushes live decisions until the client
// disconnects. A periodic comment keeps the connection alive through proxies.
func handlePdpEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	writeEvent := func(e pdpEvent) bool {
		b, err := json.Marshal(e)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: decision\ndata: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	for _, e := range feed.snapshot() {
		if !writeEvent(e) {
			return
		}
	}
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ch := feed.subscribe()
	defer feed.unsubscribe(ch)
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			if !writeEvent(e) {
				return
			}
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// handlePdpRecent returns the recent decision ring as JSON (a polling fallback
// for clients without EventSource).
func handlePdpRecent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": feed.snapshot()})
}
