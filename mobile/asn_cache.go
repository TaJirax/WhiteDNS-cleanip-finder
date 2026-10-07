package mobile

import (
	"sync"

	"whitedns-go/internal/asn"
)

// The ASN tables used to be parsed on every picker search and expansion:
// ~225 ms and ~390 MB of garbage per keystroke on a desktop CPU, several
// times that on a phone. One engine is now kept (about 16.5 MB with both
// families) and its loads are idempotent. Starting a scan releases it, so
// scans get that memory back; the picker reloads it on its next search.
var asnCache struct {
	sync.Mutex
	eng *asn.ASNEngine
}

func cachedASNEngine(dataDir string) *asn.ASNEngine {
	asnCache.Lock()
	defer asnCache.Unlock()
	if asnCache.eng == nil {
		asnCache.eng = asn.NewASNEngine(dataDir)
	}
	return asnCache.eng
}

func releaseASNCache() {
	asnCache.Lock()
	asnCache.eng = nil
	asnCache.Unlock()
}
