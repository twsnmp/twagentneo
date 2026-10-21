// Package pipeline provides an internal non-blocking event bus for twagentneo.
// Collectors publish events; exporters subscribe and consume them.
package pipeline

import (
	"log"
	"sync"
	"time"
)

// EventType identifies the kind of event being published.
type EventType int

const (
	EventTypeMetrics       EventType = iota // host resource metrics
	EventTypeNetwork                        // ARP / network state
	EventTypeAlert                          // security alert (Sigma + AI judge)
	EventTypeFIM                            // file integrity event
	EventTypeHeartbeat                      // periodic heartbeat
	EventTypeRawLog                         // raw log line from logtail (pre-Sigma)
	EventTypeResourceAlert                  // host resource threshold alert
)

// FIMPayload wraps a file integrity event for the event bus.
type FIMPayload struct {
	Event interface{} // *audit.FIMEvent — avoid import cycle; cast at consumer
}

// AlertPayload wraps a security alert for the event bus.
type AlertPayload struct {
	Alert interface{} // *audit.SecurityAlert — avoid import cycle; cast at consumer
}

// Event is the envelope carried on the internal bus.
type Event struct {
	Type      EventType
	Timestamp time.Time
	Payload   interface{} // concrete type depends on EventType
}

// Sub is a bus subscription handle. Callers read from C and call Close when done.
type Sub struct {
	C    <-chan *Event // read-only event channel
	ch   chan *Event   // bidirectional (same underlying channel)
	bus  *Bus
}

// Close unregisters the subscription and closes the channel safely.
func (s *Sub) Close() {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()

	if _, ok := s.bus.subs[s.ch]; ok {
		delete(s.bus.subs, s.ch)
		close(s.ch)
	}
}

// Bus is a multi-subscriber, non-blocking event dispatcher.
type Bus struct {
	mu   sync.RWMutex
	subs map[chan *Event]struct{}
	done chan struct{}
}

const (
	subBufferSize = 256
)

// New creates and starts a Bus. Call Stop() to shut it down cleanly.
func New() *Bus {
	return &Bus{
		subs: make(map[chan *Event]struct{}),
		done: make(chan struct{}),
	}
}

// Stop shuts down the Bus and closes all remaining subscribers.
func (b *Bus) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case <-b.done:
		return
	default:
		close(b.done)
	}

	for ch := range b.subs {
		delete(b.subs, ch)
		close(ch)
	}
}

// Publish sends an event to all subscribers non-blocking.
func (b *Bus) Publish(ev *Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	select {
	case <-b.done:
		return
	default:
	}

	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
			log.Printf("[pipeline] subscriber slow, event type=%d dropped", ev.Type)
		}
	}
}

// PublishMetrics is a convenience helper for resource metric events.
func (b *Bus) PublishMetrics(payload interface{}) {
	b.Publish(&Event{Type: EventTypeMetrics, Timestamp: time.Now(), Payload: payload})
}

// PublishNetwork is a convenience helper for network/ARP events.
func (b *Bus) PublishNetwork(payload interface{}) {
	b.Publish(&Event{Type: EventTypeNetwork, Timestamp: time.Now(), Payload: payload})
}

// PublishAlert is a convenience helper for security alert events.
func (b *Bus) PublishAlert(payload interface{}) {
	b.Publish(&Event{Type: EventTypeAlert, Timestamp: time.Now(), Payload: payload})
}

// PublishFIM is a convenience helper for FIM events.
func (b *Bus) PublishFIM(payload interface{}) {
	b.Publish(&Event{Type: EventTypeFIM, Timestamp: time.Now(), Payload: payload})
}

// PublishHeartbeat is a convenience helper for periodic heartbeat events.
func (b *Bus) PublishHeartbeat() {
	b.Publish(&Event{Type: EventTypeHeartbeat, Timestamp: time.Now()})
}

// PublishResourceAlert is a convenience helper for resource threshold alert events.
func (b *Bus) PublishResourceAlert(payload interface{}) {
	b.Publish(&Event{Type: EventTypeResourceAlert, Timestamp: time.Now(), Payload: payload})
}

// Subscribe registers a new subscriber and returns a *Sub handle.
// The caller MUST call sub.Close() when done to avoid goroutine leaks.
func (b *Bus) Subscribe() *Sub {
	ch := make(chan *Event, subBufferSize)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return &Sub{C: ch, ch: ch, bus: b}
}
