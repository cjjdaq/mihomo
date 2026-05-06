package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	"github.com/dlclark/regexp2"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
)

// dialFailedHealthCheckCooldown 失败触发的批量健康检查最小间隔
// 节点被上游封禁时，所有连接都会失败，会反复命中失败阈值；如果每次都触发批量
// 健康检查，会让 provider 持续承受高频探测形成雪崩。引入冷却窗口避免该问题。
const dialFailedHealthCheckCooldown = 5 * time.Minute

// API 触发的整组延迟测试（如 /group/{name}/delay）的抖动参数
// 不限并发，仅靠抖动错开实际握手时刻
const (
	groupURLTestJitterMaxMs = 3000
)

type GroupBase struct {
	*outbound.Base
	hidden            bool
	icon              string
	filterRegs        []*regexp2.Regexp
	excludeFilterRegs []*regexp2.Regexp
	excludeTypeArray  []string
	providers         []P.ProxyProvider
	failedTestMux     sync.Mutex
	failedTimes       int
	failedTime        time.Time
	failedTesting     atomic.Bool
	testTimeout       int
	maxFailedTimes    int
	emptyFallback     C.Proxy

	// healthCheckCooldown 记录最近一次因失败触发健康检查的时间戳（unix 秒）
	// 用于防止节点被封禁后短时间内反复触发批量健康检查导致雪崩
	lastHealthCheckTriggerSec atomic.Int64

	// for GetProxies
	getProxiesMutex  sync.Mutex
	providerVersions []uint32
	providerProxies  []C.Proxy
}

type GroupBaseOption struct {
	Name           string
	Type           C.AdapterType
	Hidden         bool
	Icon           string
	Filter         string
	ExcludeFilter  string
	ExcludeType    string
	TestTimeout    int
	MaxFailedTimes int
	EmptyFallback  C.Proxy
	Providers      []P.ProxyProvider
}

func NewGroupBase(opt GroupBaseOption) *GroupBase {
	var excludeTypeArray []string
	if opt.ExcludeType != "" {
		excludeTypeArray = strings.Split(opt.ExcludeType, "|")
	}

	var excludeFilterRegs []*regexp2.Regexp
	if opt.ExcludeFilter != "" {
		for _, excludeFilter := range strings.Split(opt.ExcludeFilter, "`") {
			excludeFilterReg := regexp2.MustCompile(excludeFilter, regexp2.None)
			excludeFilterRegs = append(excludeFilterRegs, excludeFilterReg)
		}
	}

	var filterRegs []*regexp2.Regexp
	if opt.Filter != "" {
		for _, filter := range strings.Split(opt.Filter, "`") {
			filterReg := regexp2.MustCompile(filter, regexp2.None)
			filterRegs = append(filterRegs, filterReg)
		}
	}

	gb := &GroupBase{
		Base:              outbound.NewBase(outbound.BaseOption{Name: opt.Name, Type: opt.Type}),
		hidden:            opt.Hidden,
		icon:              opt.Icon,
		filterRegs:        filterRegs,
		excludeFilterRegs: excludeFilterRegs,
		excludeTypeArray:  excludeTypeArray,
		providers:         opt.Providers,
		failedTesting:     atomic.NewBool(false),
		testTimeout:       opt.TestTimeout,
		maxFailedTimes:    opt.MaxFailedTimes,
		emptyFallback:     opt.EmptyFallback,
	}

	if gb.testTimeout == 0 {
		gb.testTimeout = 5000
	}
	if gb.maxFailedTimes == 0 {
		gb.maxFailedTimes = 5
	}

	return gb
}

func (gb *GroupBase) Hidden() bool {
	return gb.hidden
}

func (gb *GroupBase) Icon() string {
	return gb.icon
}

func (gb *GroupBase) EmptyFallback() C.Proxy {
	return gb.emptyFallback
}

func (gb *GroupBase) Touch() {
	for _, pd := range gb.providers {
		pd.Touch()
	}
}

func (gb *GroupBase) GetProxies(touch bool) []C.Proxy {
	providerVersions := make([]uint32, len(gb.providers))
	for i, pd := range gb.providers {
		if touch { // touch first
			pd.Touch()
		}
		providerVersions[i] = pd.Version()
	}

	// thread safe
	gb.getProxiesMutex.Lock()
	defer gb.getProxiesMutex.Unlock()

	// return the cached proxies if version not changed
	if slices.Equal(providerVersions, gb.providerVersions) {
		return gb.providerProxies
	}

	var proxies []C.Proxy
	if len(gb.filterRegs) == 0 {
		for _, pd := range gb.providers {
			proxies = append(proxies, pd.Proxies()...)
		}
	} else {
		for _, pd := range gb.providers {
			if pd.VehicleType() == P.Compatible { // compatible provider unneeded filter
				proxies = append(proxies, pd.Proxies()...)
				continue
			}

			var newProxies []C.Proxy
			proxiesSet := map[string]struct{}{}
			for _, filterReg := range gb.filterRegs {
				for _, p := range pd.Proxies() {
					name := p.Name()
					if mat, _ := filterReg.MatchString(name); mat {
						if _, ok := proxiesSet[name]; !ok {
							proxiesSet[name] = struct{}{}
							newProxies = append(newProxies, p)
						}
					}
				}
			}
			proxies = append(proxies, newProxies...)
		}
	}

	// Multiple filers means that proxies are sorted in the order in which the filers appear.
	// Although the filter has been performed once in the previous process,
	// when there are multiple providers, the array needs to be reordered as a whole.
	if len(gb.providers) > 1 && len(gb.filterRegs) > 1 {
		var newProxies []C.Proxy
		proxiesSet := map[string]struct{}{}
		for _, filterReg := range gb.filterRegs {
			for _, p := range proxies {
				name := p.Name()
				if mat, _ := filterReg.MatchString(name); mat {
					if _, ok := proxiesSet[name]; !ok {
						proxiesSet[name] = struct{}{}
						newProxies = append(newProxies, p)
					}
				}
			}
		}
		for _, p := range proxies { // add not matched proxies at the end
			name := p.Name()
			if _, ok := proxiesSet[name]; !ok {
				proxiesSet[name] = struct{}{}
				newProxies = append(newProxies, p)
			}
		}
		proxies = newProxies
	}

	if len(gb.excludeFilterRegs) > 0 {
		var newProxies []C.Proxy
	LOOP1:
		for _, p := range proxies {
			name := p.Name()
			for _, excludeFilterReg := range gb.excludeFilterRegs {
				if mat, _ := excludeFilterReg.MatchString(name); mat {
					continue LOOP1
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if gb.excludeTypeArray != nil {
		var newProxies []C.Proxy
	LOOP2:
		for _, p := range proxies {
			mType := p.Type().String()
			for _, excludeType := range gb.excludeTypeArray {
				if strings.EqualFold(mType, excludeType) {
					continue LOOP2
				}
			}
			newProxies = append(newProxies, p)
		}
		proxies = newProxies
	}

	if len(proxies) == 0 {
		return []C.Proxy{gb.EmptyFallback()}
	}

	// only cache when proxies not empty
	gb.providerVersions = providerVersions
	gb.providerProxies = proxies

	return proxies
}

func (gb *GroupBase) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (map[string]uint16, error) {
	var lock sync.Mutex
	mp := map[string]uint16{}
	proxies := gb.GetProxies(false)

	// 不限并发，仅靠随机抖动错开实际握手时刻
	// N 节点 / W 窗口 ≈ N/W * 1000 RPS，对反滥用防护是远低于"全部同时拨"的
	eg := new(errgroup.Group)
	for _, proxy := range proxies {
		proxy := proxy
		eg.Go(func() error {
			if groupURLTestJitterMaxMs > 0 {
				jitter := time.Duration(rand.Intn(groupURLTestJitterMaxMs)) * time.Millisecond
				timer := time.NewTimer(jitter)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return nil
				}
			}
			delay, err := proxy.URLTest(ctx, url, expectedStatus)
			if err == nil {
				lock.Lock()
				mp[proxy.Name()] = delay
				lock.Unlock()
			}
			return nil
		})
	}
	_ = eg.Wait()

	if len(mp) == 0 {
		return mp, fmt.Errorf("get delay: all proxies timeout")
	} else {
		return mp, nil
	}
}

func (gb *GroupBase) onDialFailed(adapterType C.AdapterType, err error, fn func()) {
	if adapterType == C.Direct || adapterType == C.Compatible || adapterType == C.Reject || adapterType == C.Pass || adapterType == C.RejectDrop {
		return
	}

	if errors.Is(err, C.ErrNotSupport) {
		return
	}

	// triggerHealthCheck 包装实际的健康检查触发，应用冷却窗口避免雪崩
	triggerHealthCheck := func() {
		nowSec := time.Now().Unix()
		lastSec := gb.lastHealthCheckTriggerSec.Load()
		cooldownSec := int64(dialFailedHealthCheckCooldown / time.Second)
		if lastSec > 0 && nowSec-lastSec < cooldownSec {
			log.Debugln("ProxyGroup: %s health check skipped due to cooldown (%ds remaining)",
				gb.Name(), cooldownSec-(nowSec-lastSec))
			return
		}
		// CAS 防止并发多个 goroutine 同时通过冷却检查
		if !gb.lastHealthCheckTriggerSec.CompareAndSwap(lastSec, nowSec) {
			return
		}
		fn()
	}

	go func() {
		if strings.Contains(err.Error(), "connection refused") {
			triggerHealthCheck()
			return
		}

		gb.failedTestMux.Lock()
		defer gb.failedTestMux.Unlock()

		gb.failedTimes++
		if gb.failedTimes == 1 {
			log.Debugln("ProxyGroup: %s first failed", gb.Name())
			gb.failedTime = time.Now()
		} else {
			if time.Since(gb.failedTime) > time.Duration(gb.testTimeout)*time.Millisecond {
				gb.failedTimes = 0
				return
			}

			log.Debugln("ProxyGroup: %s failed count: %d", gb.Name(), gb.failedTimes)
			if gb.failedTimes >= gb.maxFailedTimes {
				log.Warnln("because %s failed multiple times, activate health check", gb.Name())
				triggerHealthCheck()
			}
		}
	}()
}

func (gb *GroupBase) healthCheck() {
	if gb.failedTesting.Load() {
		return
	}

	gb.failedTesting.Store(true)
	wg := sync.WaitGroup{}
	for _, proxyProvider := range gb.providers {
		wg.Add(1)
		proxyProvider := proxyProvider
		go func() {
			defer wg.Done()
			proxyProvider.HealthCheck()
		}()
	}

	wg.Wait()
	gb.failedTesting.Store(false)
	gb.failedTimes = 0
}

func (gb *GroupBase) onDialSuccess() {
	if !gb.failedTesting.Load() {
		gb.failedTimes = 0
	}
}
