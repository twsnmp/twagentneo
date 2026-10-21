//go:build windows

package logtail

import (
	"encoding/json"
	"encoding/xml"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modwevtapi                = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe          = modwevtapi.NewProc("EvtSubscribe")
	procEvtNext               = modwevtapi.NewProc("EvtNext")
	procEvtClose              = modwevtapi.NewProc("EvtClose")
	procEvtRender             = modwevtapi.NewProc("EvtRender")
	modkernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procCreateEventW          = modkernel32.NewProc("CreateEventW")
	procWaitForSingleObject   = modkernel32.NewProc("WaitForSingleObject")
)

const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXml          = 1
	waitObject0                = 0
)

// defaultSources returns Windows Event Log channels to monitor.
func defaultSources() []string {
	return []string{
		"Security",
		"System",
	}
}

func inode(_ *os.File) uint64 {
	return 0
}

func rotated(_ string, _ uint64) bool {
	return false
}

// winEventXML represents the minimal structure of a Windows Event Log XML record.
type winEventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int    `xml:"EventID"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// tailSource begins monitoring a Windows Event Log channel.
func (t *Tailer) tailSource(channel string) {
	defer t.wg.Done()

	// Create a manual-reset event handle for notifications
	hEvent, _, err := procCreateEventW.Call(0, 1, 0, 0)
	if hEvent == 0 {
		log.Printf("[logtail] CreateEventW failed for %s: %v", channel, err)
		return
	}
	defer syscall.CloseHandle(syscall.Handle(hEvent))

	chanPtr, _ := windows.UTF16PtrFromString(channel)

	// Subscribe to future events
	hSub, _, err := procEvtSubscribe.Call(
		0,                                    // Session
		hEvent,                               // SignalEvent
		uintptr(unsafe.Pointer(chanPtr)),     // ChannelPath
		0,                                    // Query (null = all)
		0,                                    // Bookmark
		0,                                    // Context
		0,                                    // Callback (null = pull mode)
		uintptr(evtSubscribeToFutureEvents),  // Flags
	)
	if hSub == 0 {
		log.Printf("[logtail] EvtSubscribe failed for %s: %v", channel, err)
		return
	}
	defer procEvtClose.Call(hSub)

	log.Printf("[logtail] subscribed to Windows Event Log channel: %s", channel)

	bufSize := uint32(4096)
	buf := make([]uint16, bufSize)

	for {
		select {
		case <-t.done:
			return
		default:
		}

		// Wait for new event signal (500ms timeout to check t.done)
		res, _, _ := procWaitForSingleObject.Call(hEvent, 500)
		if res != waitObject0 {
			continue
		}

		// Pull available events
		for {
			var hEvt uintptr
			var returned uint32
			r, _, _ := procEvtNext.Call(hSub, 1, uintptr(unsafe.Pointer(&hEvt)), 0, 0, uintptr(unsafe.Pointer(&returned)))
			if r == 0 || returned == 0 {
				break
			}

			// Render event as XML
			var bufUsed, propCount uint32
			rRender, _, _ := procEvtRender.Call(
				0,
				hEvt,
				uintptr(evtRenderEventXml),
				uintptr(bufSize*2),
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(unsafe.Pointer(&bufUsed)),
				uintptr(unsafe.Pointer(&propCount)),
			)

			if rRender != 0 {
				xmlStr := windows.UTF16ToString(buf[:bufUsed/2])
				normalized := normalizeWindowsEvent(channel, xmlStr)
				if normalized != "" {
					select {
					case t.eventCh <- &LogEvent{
						Timestamp: time.Now(),
						Source:    channel,
						Line:      normalized,
					}:
					case <-t.done:
						procEvtClose.Call(hEvt)
						return
					}
				}
			}
			procEvtClose.Call(hEvt)
		}
	}
}

// normalizeWindowsEvent parses XML and transforms it into a flattened JSON string
// compatible with the Sigma evaluation engine.
func normalizeWindowsEvent(channel, xmlStr string) string {
	var evt winEventXML
	if err := xml.Unmarshal([]byte(xmlStr), &evt); err != nil {
		return ""
	}

	record := make(map[string]interface{})
	record["Channel"] = channel
	record["ProviderName"] = evt.System.Provider.Name
	record["EventID"] = evt.System.EventID
	record["Computer"] = evt.System.Computer

	for _, d := range evt.EventData.Data {
		if d.Name != "" {
			record[d.Name] = d.Value
		}
	}

	data, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	return string(data)
}
