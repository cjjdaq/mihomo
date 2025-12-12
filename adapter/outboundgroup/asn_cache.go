package outboundgroup

import (
	"math/rand"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/log"
)

// ---- ASN 缓存常量 ----
const (
	// ASN 缓存维护参数
	asnCacheCleanupInterval = 6 * time.Hour
	asnCacheMaxEntries      = 200000

	// ASN 缓存 TTL（正向长缓存，负向短缓存）
	asnCachePositiveTTL = 7 * 24 * time.Hour
	asnCacheNegativeTTL = 2 * time.Hour
)

// ---- 全局 ASN 缓存实例 ----
var (
	globalASNCache    asnIPCache
	globalASNInterner stringInterner
)

// ================ IP Key（避免分配） ================
// IPv4: kind=4 + uint32
// IPv6: kind=6 + [16]byte
type ipKey struct {
	kind uint8 // 4 or 6
	v4   uint32
	v6   [16]byte
}

func makeIPKey(ip netip.Addr) (ipKey, bool) {
	if !ip.IsValid() {
		return ipKey{}, false
	}
	if ip.Is4() {
		b := ip.As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		return ipKey{kind: 4, v4: v}, true
	}
	b := ip.As16()
	var a [16]byte
	copy(a[:], b[:])
	return ipKey{kind: 6, v6: a}, true
}

// ================ ASN 缓存条目 ================
type asnCacheEntry struct {
	asn      string
	aso      string
	expireAt int64 // unix nano，快速比较
}

// ================ 最小化 singleflight（按 key 去重并发请求） ================
type flightGroup struct {
	mu sync.Mutex
	m  map[ipKey]*flightCall
}

type flightCall struct {
	wg  sync.WaitGroup
	res asnCacheEntry
}

func (g *flightGroup) do(k ipKey, fn func() asnCacheEntry) asnCacheEntry {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[ipKey]*flightCall, 1024)
	}
	if c, ok := g.m[k]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.res
	}
	c := &flightCall{}
	c.wg.Add(1)
	g.m[k] = c
	g.mu.Unlock()

	c.res = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, k)
	g.mu.Unlock()
	return c.res
}

// ================ 分片 map 缓存 ================
const asnShardCount = 64 // 2 的幂次

type asnShard struct {
	mu sync.RWMutex
	m  map[ipKey]asnCacheEntry
}

type asnIPCache struct {
	shards [asnShardCount]asnShard
	sf     flightGroup
}

func (c *asnIPCache) shardFor(k ipKey) *asnShard {
	var h uint64
	h = uint64(k.kind) * 1315423911
	if k.kind == 4 {
		h ^= uint64(k.v4) * 2654435761
	} else {
		h ^= uint64(uint32(k.v6[0])<<24|uint32(k.v6[1])<<16|uint32(k.v6[2])<<8|uint32(k.v6[3])) * 2246822519
		h ^= uint64(uint32(k.v6[12])<<24|uint32(k.v6[13])<<16|uint32(k.v6[14])<<8|uint32(k.v6[15])) * 3266489917
	}
	return &c.shards[h&(asnShardCount-1)]
}

func (c *asnIPCache) get(k ipKey, nowN int64) (asnCacheEntry, bool) {
	s := c.shardFor(k)
	s.mu.RLock()
	if s.m == nil {
		s.mu.RUnlock()
		return asnCacheEntry{}, false
	}
	e, ok := s.m[k]
	s.mu.RUnlock()
	if !ok {
		return asnCacheEntry{}, false
	}
	if nowN <= e.expireAt {
		return e, true
	}
	// 已过期：尽力删除
	s.mu.Lock()
	if s.m != nil {
		e2, ok2 := s.m[k]
		if ok2 && nowN > e2.expireAt {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
	return asnCacheEntry{}, false
}

func (c *asnIPCache) set(k ipKey, e asnCacheEntry) {
	s := c.shardFor(k)
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[ipKey]asnCacheEntry, 256)
	}
	s.m[k] = e
	s.mu.Unlock()
}

func (c *asnIPCache) cleanup(nowN int64, maxEntries int) (expired int, total int) {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		if s.m == nil {
			s.mu.Unlock()
			continue
		}
		for k, e := range s.m {
			total++
			if nowN > e.expireAt {
				delete(s.m, k)
				expired++
				total--
			}
		}
		s.mu.Unlock()
	}

	if total <= maxEntries {
		return
	}

	need := total - maxEntries
	need += maxEntries / 20 // +5% 滞后余量
	if need < 1000 {
		need = 1000
	}

	for i := range c.shards {
		if need <= 0 {
			break
		}
		s := &c.shards[i]
		s.mu.Lock()
		if s.m == nil {
			s.mu.Unlock()
			continue
		}
		for k, e := range s.m {
			if need <= 0 {
				break
			}
			rem := e.expireAt - nowN
			if rem < int64(48*time.Hour) || rand.Intn(10) == 0 {
				delete(s.m, k)
				need--
			}
		}
		s.mu.Unlock()
	}
	return
}

// ================ 字符串驻留（ASN/ASO 去重，带容量限制） ================
const stringInternerMaxSize = 100000 // 最大驻留字符串数量

type stringInterner struct {
	mu sync.RWMutex
	m  map[string]string
}

func (si *stringInterner) intern(s string) string {
	if s == "" {
		return ""
	}
	si.mu.RLock()
	if si.m != nil {
		if v, ok := si.m[s]; ok {
			si.mu.RUnlock()
			return v
		}
	}
	si.mu.RUnlock()

	si.mu.Lock()
	if si.m == nil {
		si.m = make(map[string]string, 1024)
	}
	if v, ok := si.m[s]; ok {
		si.mu.Unlock()
		return v
	}
	// 超过容量上限时不再驻留新字符串，直接返回
	if len(si.m) >= stringInternerMaxSize {
		si.mu.Unlock()
		return s
	}
	si.m[s] = s
	si.mu.Unlock()
	return s
}

// ================ Smart 上的 ASN 缓存方法 ================

// cleanupASNCache 清理过期的 ASN 缓存条目
func (s *Smart) cleanupASNCache() {
	nowN := time.Now().UnixNano()
	expired, total := globalASNCache.cleanup(nowN, asnCacheMaxEntries)
	if expired > 0 {
		log.Debugln("[Smart] ASN cache cleanup: expired=%d total~%d", expired, total)
	}
}

// lookupASNByIPCached 带缓存的 ASN 查找
func (s *Smart) lookupASNByIPCached(ip netip.Addr) (string, string) {
	if !ip.IsValid() {
		return "", ""
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
		return "", ""
	}

	k, ok := makeIPKey(ip)
	if !ok {
		return "", ""
	}

	nowN := time.Now().UnixNano()
	if e, ok := globalASNCache.get(k, nowN); ok {
		log.Debugln("[Smart][ASN] cache hit: %s -> %s %s", ip.String(), e.asn, e.aso)
		return e.asn, e.aso
	}

	e := globalASNCache.sf.do(k, func() asnCacheEntry {
		nowN2 := time.Now().UnixNano()
		if e2, ok2 := globalASNCache.get(k, nowN2); ok2 {
			return e2
		}

		asn, aso := mmdb.ASNInstance().LookupASN(ip.AsSlice())
		asn = globalASNInterner.intern(asn)
		aso = globalASNInterner.intern(aso)

		if asn == "" {
			exp := time.Now().Add(asnCacheNegativeTTL).UnixNano()
			ne := asnCacheEntry{asn: "", aso: "", expireAt: exp}
			globalASNCache.set(k, ne)
			return ne
		}

		ttl := asnCachePositiveTTL
		j := time.Duration(rand.Int63n(int64(6*time.Hour))) - 3*time.Hour
		ttl += j
		if ttl < 24*time.Hour {
			ttl = 24 * time.Hour
		}
		exp := time.Now().Add(ttl).UnixNano()
		pe := asnCacheEntry{asn: asn, aso: aso, expireAt: exp}
		globalASNCache.set(k, pe)
		return pe
	})

	return e.asn, e.aso
}
