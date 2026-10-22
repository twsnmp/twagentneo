package pipeline

import (
	"sync"
	"testing"
	"time"
)

func TestBusPubSub(t *testing.T) {
	bus := New()
	defer bus.Stop()

	sub := bus.Subscribe()
	defer sub.Close()

	testMetric := map[string]interface{}{"cpu": 25.5}
	bus.PublishMetrics(testMetric)

	select {
	case ev := <-sub.C:
		if ev.Type != EventTypeMetrics {
			t.Fatalf("expected EventTypeMetrics, got %v", ev.Type)
		}
		m, ok := ev.Payload.(map[string]interface{})
		if !ok || m["cpu"] != 25.5 {
			t.Fatalf("unexpected payload: %v", ev.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestBusMultipleSubscribers(t *testing.T) {
	bus := New()
	defer bus.Stop()

	sub1 := bus.Subscribe()
	defer sub1.Close()

	sub2 := bus.Subscribe()
	defer sub2.Close()

	bus.PublishAlert("test-alert")

	var wg sync.WaitGroup
	wg.Add(2)

	checkSub := func(s *Sub) {
		defer wg.Done()
		select {
		case ev := <-s.C:
			if ev.Type != EventTypeAlert || ev.Payload != "test-alert" {
				t.Errorf("unexpected event: %v", ev)
			}
		case <-time.After(2 * time.Second):
			t.Error("timed out waiting for event")
		}
	}

	go checkSub(sub1)
	go checkSub(sub2)
	wg.Wait()
}

func TestBusUnsubscribe(t *testing.T) {
	bus := New()
	defer bus.Stop()

	sub := bus.Subscribe()
	sub.Close()

	time.Sleep(50 * time.Millisecond)
	bus.PublishHeartbeat()

	// Channel should be closed
	select {
	case _, ok := <-sub.C:
		if ok {
			t.Error("expected channel to be closed after unsubscribe")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("channel was not closed")
	}
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		ev   EventType
		want string
	}{
		{EventTypeMetrics, "Metrics"},
		{EventTypeInterface, "Interface"},
		{EventTypeARP, "ARP"},
		{EventTypeTCP, "TCP"},
		{EventTypeAlert, "Alert"},
		{EventTypeFIM, "FIM"},
		{EventTypeHeartbeat, "Heartbeat"},
		{EventTypeRawLog, "RawLog"},
		{EventTypeResourceAlert, "ResourceAlert"},
		{EventType(999), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.ev.String(); got != tt.want {
			t.Errorf("EventType(%d).String() = %q, want %q", tt.ev, got, tt.want)
		}
	}
}
