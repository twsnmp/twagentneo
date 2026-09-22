// Package pipeline provides an internal non-blocking event bus for twagentneo.
// Collectors publish events; exporters subscribe and consume them.
package pipeline

import (
	"log"
	"time"
)

// EventType identifies the kind of event being published.
type EventType int

const (
	EventTypeMetrics   EventType = iota // host resource metrics
	EventTypeNetwork                    // ARP / network state
	EventTypeAlert                      // security alert (Sigma + AI judge)
	EventTypeFIM                        // file integrity event
	EventTypeHeartbeat                  // periodic heartbeat
	EventTypeRawLog                     // raw log line from logtail (pre-Sigma)
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

// Close unregisters the subscription and drains the channel.
func (s *Sub) Close() {
	s.bus.unsubscribe <- s.ch
}

// Bus is a multi-subscriber, non-blocking event dispatcher.
type Bus struct {
	in          chan *Event
	subscribe   chan chan *Event
	unsubscribe chan chan *Event
	done        chan struct{}
}

const (
	busBufferSize = 4096
	subBufferSize = 256
)

// New creates and starts a Bus. Call Stop() to shut it down cleanly.
func New() *Bus {
	b := &Bus{
		in:          make(chan *Event, busBufferSize),
		subscribe:   make(chan chan *Event, 8),
		unsubscribe: make(chan chan *Event, 8),
		done:        make(chan struct{}),
	}
	go b.run()
	return b
}

// run is the Bus dispatch loop.
func (b *Bus) run() {
	subs := make(map[chan *Event]struct{})
	for {
		select {
		case <-b.done:
			return

		case ch := <-b.subscribe:
			subs[ch] = struct{}{}

		case ch := <-b.unsubscribe:
			delete(subs, ch)
			close(ch)

		case ev := <-b.in:
			for ch := range subs {
				select {
				case ch <- ev:
				default:
					log.Printf("[pipeline] subscriber slow, event type=%d dropped", ev.Type)
				}
			}
		}
	}
}

// Stop shuts down the Bus dispatch loop.
func (b *Bus) Stop() {
	close(b.done)
}

// Publish sends an event to the bus non-blocking.
func (b *Bus) Publish(ev *Event) {
	select {
	case b.in <- ev:
	default:
		log.Printf("[pipeline] bus input full, event type=%d dropped", ev.Type)
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

// Subscribe registers a new subscriber and returns a *Sub handle.
// The caller MUST call sub.Close() when done to avoid goroutine leaks.
func (b *Bus) Subscribe() *Sub {
	ch := make(chan *Event, subBufferSize)
	b.subscribe <- ch
	return &Sub{C: ch, ch: ch, bus: b}
}
