package common

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/component/sniffer"
	C "github.com/metacubex/mihomo/constant"
)

type NetworkType struct {
	Base
	network C.NetWork
	adapter string
}

func NewNetworkType(network, adapter string) (*NetworkType, error) {
	ntType := NetworkType{
		Base: Base{},
	}

	ntType.adapter = adapter
	switch strings.ToUpper(network) {
	case "TCP":
		ntType.network = C.TCP
	case "UDP":
		ntType.network = C.UDP
	case "QUIC":
		ntType.network = C.QUIC
	default:
		return nil, fmt.Errorf("unsupported network type, only TCP/UDP/QUIC")
	}

	return &ntType, nil
}

func (n *NetworkType) RuleType() C.RuleType {
	return C.Network
}

func (n *NetworkType) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	// QUIC is an application-layer protocol: it is never carried by
	// Metadata.NetWork (which stays UDP), only by Metadata.SniffProtocol.
	// The transport check is kept because QUIC always runs over UDP, so a
	// TCP connection carrying a stale sniffed value must not match.
	// The protocol name comes from the sniffer's own constant so the two
	// layers cannot drift apart.
	if n.network == C.QUIC {
		return metadata.NetWork == C.UDP && metadata.SniffProtocol == sniffer.ProtocolQUIC, n.adapter
	}
	return n.network == metadata.NetWork, n.adapter
}

func (n *NetworkType) Adapter() string {
	return n.adapter
}

func (n *NetworkType) Payload() string {
	return n.network.String()
}

var _ C.Rule = (*NetworkType)(nil)
