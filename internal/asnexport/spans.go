package asnexport

import (
	"net"
	"sort"
	"strconv"
)

// IPv4Span is an inclusive run of IPv4 addresses held as integers. Expanding
// spans instead of net.IP values avoids a String() allocation per address,
// and merging them removes the duplicates overlapping ASN ranges produce.
type IPv4Span struct{ First, Last uint64 }

// IPv4SpanOf returns ipnet's addresses as a span; ok is false for IPv6.
func IPv4SpanOf(ipnet *net.IPNet) (IPv4Span, bool) {
	v4 := ipnet.IP.To4()
	if v4 == nil {
		return IPv4Span{}, false
	}
	ones, _ := ipnet.Mask.Size()
	size := uint64(1) << uint(32-ones)
	first := (uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3])) &^ (size - 1)
	return IPv4Span{first, first + size - 1}, true
}

// MergeIPv4Spans sorts spans and joins overlapping or adjacent ones in place.
func MergeIPv4Spans(spans []IPv4Span) []IPv4Span {
	sort.Slice(spans, func(i, j int) bool { return spans[i].First < spans[j].First })
	merged := spans[:0]
	for _, s := range spans {
		if n := len(merged); n > 0 && s.First <= merged[n-1].Last+1 {
			if s.Last > merged[n-1].Last {
				merged[n-1].Last = s.Last
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

// AppendIPv4 appends v as dotted-quad text without allocating.
func AppendIPv4(dst []byte, v uint32) []byte {
	dst = strconv.AppendUint(dst, uint64(v>>24), 10)
	dst = append(dst, '.')
	dst = strconv.AppendUint(dst, uint64(v>>16&0xff), 10)
	dst = append(dst, '.')
	dst = strconv.AppendUint(dst, uint64(v>>8&0xff), 10)
	dst = append(dst, '.')
	return strconv.AppendUint(dst, uint64(v&0xff), 10)
}
