package route

import (
	"fmt"
	"net"
	"sort"
	"strings"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/listener"
	IN "github.com/metacubex/mihomo/listener/inbound"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

type listenerInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Proxy    string `json:"proxy,omitempty"`
	User     string `json:"user,omitempty"`
	Pass     string `json:"pass,omitempty"`
	PoolPort bool   `json:"pool-port,omitempty"`
}

// listenerInfoOf builds the API representation of an inbound listener.
func listenerInfoOf(l interface {
	Address() string
	Name() string
}) listenerInfo {
	info := listenerInfo{
		Name:    l.Name(),
		Address: l.Address(),
	}
	switch v := l.(type) {
	case *IN.HTTP:
		info.Type = "http"
		info.Proxy = v.SpecialProxy()
		info.PoolPort = v.PoolPort()
		if users := v.Users(); len(users) > 0 {
			info.User, info.Pass = users[0].Username, users[0].Password
		}
	case *IN.Socks:
		info.Type = "socks"
		info.Proxy = v.SpecialProxy()
		info.PoolPort = v.PoolPort()
		if users := v.Users(); len(users) > 0 {
			info.User, info.Pass = users[0].Username, users[0].Password
		}
	case *IN.Mixed:
		info.Type = "mixed"
		info.Proxy = v.SpecialProxy()
		info.PoolPort = v.PoolPort()
		if users := v.Users(); len(users) > 0 {
			info.User, info.Pass = users[0].Username, users[0].Password
		}
	default:
		info.Type = "unknown"
	}
	return info
}

// matchKeywords reports whether s contains any comma-separated keyword (substring match).
func matchKeywords(s, keywords string) bool {
	for _, kw := range strings.Split(keywords, ",") {
		kw = strings.TrimSpace(kw)
		if kw != "" && strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func listenerRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getListeners)
	return r
}

func getListeners(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	filter := strings.ToLower(query.Get("type"))
	format := query.Get("format")
	include := strings.ToLower(strings.Join(query["include"], ","))
	exclude := strings.ToLower(strings.Join(query["exclude"], ","))
	providersFilter := strings.ToLower(strings.Join(query["provider"], ","))

	// provider 订阅筛选：构建 订阅名 → 节点名 集合（跳过 default 聚合 provider）
	var providerNodes map[string]map[string]bool
	if providersFilter != "" {
		providerNodes = make(map[string]map[string]bool)
		for name, pd := range tunnel.Providers() {
			if pd.VehicleType() == P.Compatible {
				continue
			}
			nodes := make(map[string]bool)
			for _, p := range pd.Proxies() {
				nodes[strings.ToLower(p.Name())] = true
			}
			providerNodes[strings.ToLower(name)] = nodes
		}
	}

	infos := make([]listenerInfo, 0, 16)
	for _, l := range listener.InboundListeners() {
		info := listenerInfoOf(l)
		switch filter {
		case "http":
			if info.Type != "http" && info.Type != "mixed" {
				continue
			}
		case "socks":
			if info.Type != "socks" && info.Type != "mixed" {
				continue
			}
		case "mixed":
			if info.Type != "mixed" {
				continue
			}
		}
		// provider 筛选：绑定的节点必须属于指定订阅之一
		if providersFilter != "" {
			matched := false
			lowerProxy := strings.ToLower(info.Proxy)
			for _, name := range strings.Split(providersFilter, ",") {
				name = strings.TrimSpace(name)
				if nodes, ok := providerNodes[name]; ok && nodes[lowerProxy] {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		// include/exclude match against both listener name and bound proxy
		if include != "" && !matchKeywords(strings.ToLower(info.Name), include) && !matchKeywords(strings.ToLower(info.Proxy), include) {
			continue
		}
		if exclude != "" && (matchKeywords(strings.ToLower(info.Name), exclude) || matchKeywords(strings.ToLower(info.Proxy), exclude)) {
			continue
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })

	switch format {
	case "resin":
		// Resin subscribable format: only proxy-port-pool auto ports
		// (manual listeners in the config are deliberately excluded).
		// URI line scheme://[user:pass@]host:port#tag.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		host := query.Get("host")
		if host == "" {
			host = "127.0.0.1"
		}
		for _, info := range infos {
			if !info.PoolPort {
				continue // only proxy-port-pool listeners
			}
			_, port, err := net.SplitHostPort(info.Address)
			if err != nil {
				continue
			}
			if info.User != "" {
				_, _ = fmt.Fprintf(w, "http://%s:%s@%s:%s#%s\n", info.User, info.Pass, host, port, info.Name)
			} else {
				_, _ = fmt.Fprintf(w, "http://%s:%s#%s\n", host, port, info.Name)
			}
		}
		return
	case "plain":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, info := range infos {
			if info.Proxy != "" {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\n", info.Name, info.Address, info.Proxy)
			} else {
				_, _ = fmt.Fprintf(w, "%s\t%s\n", info.Name, info.Address)
			}
		}
		return
	}

	render.JSON(w, r, render.M{"listeners": infos})
}
