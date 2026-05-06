package outbound

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/anytls"
	"github.com/metacubex/mihomo/transport/vmess"

	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type AnyTLS struct {
	*Base
	client *anytls.Client
	option *AnyTLSOption
}

type AnyTLSOption struct {
	BasicOption
	Name                     string           `proxy:"name"`
	Server                   string           `proxy:"server"`
	Port                     int              `proxy:"port"`
	Password                 string           `proxy:"password"`
	ALPN                     []string         `proxy:"alpn,omitempty"`
	SNI                      string           `proxy:"sni,omitempty"`
	ECHOpts                  ECHOptions       `proxy:"ech-opts,omitempty"`
	ShadowTLSOpts            ShadowTLSOptions `proxy:"shadow-tls-opts,omitempty"`
	RestlsOpts               RestlsOptions    `proxy:"restls-opts,omitempty"`
	JLSOpts                  JLSOptions       `proxy:"jls-opts,omitempty"`
	ClientFingerprint        string           `proxy:"client-fingerprint,omitempty"`
	SkipCertVerify           bool             `proxy:"skip-cert-verify,omitempty"`
	NameCertVerify           string           `proxy:"name-cert-verify,omitempty"`
	Fingerprint              string           `proxy:"fingerprint,omitempty"`
	Certificate              string           `proxy:"certificate,omitempty"`
	PrivateKey               string           `proxy:"private-key,omitempty"`
	UDP                      bool             `proxy:"udp,omitempty"`
	ClientMetadata           string           `proxy:"client-metadata,omitempty"`
	IdleSessionCheckInterval int              `proxy:"idle-session-check-interval,omitempty"`
	IdleSessionTimeout       int              `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession           int              `proxy:"min-idle-session,omitempty"`
	DisableReuse             bool             `proxy:"disable-reuse,omitempty"`
}

func (t *AnyTLS) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	c, err := t.client.CreateProxy(ctx, M.ParseSocksaddrHostPort(metadata.String(), metadata.DstPort))
	if err != nil {
		return nil, err
	}
	return NewConn(c, t), nil
}

func (t *AnyTLS) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = t.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	// create tcp
	c, err := t.client.CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		return nil, err
	}

	// create uot on tcp
	destination := M.SocksaddrFromNet(metadata.UDPAddr())
	return NewPacketConn(N.NewThreadSafePacketConn(uot.NewLazyConn(c, uot.Request{Destination: destination})), t), nil
}

// SupportUOT implements C.ProxyAdapter
func (t *AnyTLS) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (t *AnyTLS) ProxyInfo() C.ProxyInfo {
	info := t.Base.ProxyInfo()
	info.DialerProxy = t.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (t *AnyTLS) Close() error {
	return t.client.Close()
}

func NewAnyTLS(option AnyTLSOption) (*AnyTLS, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &AnyTLS{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.AnyTLS,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	singDialer := proxydialer.NewSingDialer(outbound.dialer)

	tOption := anytls.ClientConfig{
		Password:                 option.Password,
		Server:                   M.ParseSocksaddrHostPort(option.Server, uint16(option.Port)),
		Dialer:                   singDialer,
		ClientMetadata:           option.ClientMetadata,
		IdleSessionCheckInterval: time.Duration(option.IdleSessionCheckInterval) * time.Second,
		IdleSessionTimeout:       time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdleSession:           option.MinIdleSession,
		DisableReuse:             option.DisableReuse,
		Name:                     option.Name,
	}
	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}
	shadowTLSConfig, err := option.ShadowTLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	restlsConfig, err := option.RestlsOpts.Parse(option.SNI, option.ClientFingerprint)
	if err != nil {
		return nil, err
	}
	jlsConfig, err := option.JLSOpts.Parse()
	if err != nil {
		return nil, err
	}
	securityModes := make([]string, 0, 3)
	if shadowTLSConfig != nil {
		securityModes = append(securityModes, "ShadowTLS")
	}
	if restlsConfig != nil {
		securityModes = append(securityModes, "Restls")
	}
	if jlsConfig != nil {
		securityModes = append(securityModes, "JLS")
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	tlsConfig := &vmess.TLSConfig{
		Host:              option.SNI,
		SkipCertVerify:    option.SkipCertVerify,
		NameCertVerify:    option.NameCertVerify,
		NextProtos:        option.ALPN,
		FingerPrint:       option.Fingerprint,
		Certificate:       option.Certificate,
		PrivateKey:        option.PrivateKey,
		ClientFingerprint: option.ClientFingerprint,
		ECH:               echConfig,
		ShadowTLS:         shadowTLSConfig,
		Restls:            restlsConfig,
		JLS:               jlsConfig,
	}
	if tlsConfig.Host == "" {
		tlsConfig.Host = option.Server
	}
	tOption.TLSConfig = tlsConfig

	client := anytls.NewClient(context.TODO(), tOption)
	outbound.client = client

	// 启动主动预热：异步建立 min-idle-session 个 TLS 会话放入空闲池
	// 让节点启动后第一个真实请求即可 0-RTT 复用，避免冷启动握手延迟
	// disable-reuse 时无空闲池，预热无意义
	if !option.DisableReuse && option.MinIdleSession > 0 {
		go warmupAnyTLSSessions(option.Name, client, option.MinIdleSession)
	}

	return outbound, nil
}

// warmupAnyTLSSessions 后台逐个建立空闲会话，避免一次性突发握手
//
// 单次会话建立失败不阻塞后续，只记录调试日志：节点本身不可用时
// 真实流量也会失败，预热失败属于预期可恢复情况。
func warmupAnyTLSSessions(name string, client *anytls.Client, count int) {
	const (
		warmupDialTimeout    = 8 * time.Second
		warmupSessionDelayMs = 200 // 会话间间隔，防止瞬时多个 TLS 握手集中
	)

	// 启动后稍等片刻，让 mihomo 初始化完成（DNS、interface 绑定等）
	time.Sleep(2 * time.Second)

	for i := 0; i < count; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), warmupDialTimeout)
		err := client.Warmup(ctx)
		cancel()
		if err != nil {
			log.Debugln("[AnyTLS] %s warmup session %d/%d failed: %v", name, i+1, count, err)
		} else {
			log.Debugln("[AnyTLS] %s warmup session %d/%d ok", name, i+1, count)
		}
		if i < count-1 {
			time.Sleep(warmupSessionDelayMs * time.Millisecond)
		}
	}
}
