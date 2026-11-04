package common

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/assert"
)

func TestNetworkTypeQUIC(t *testing.T) {
	nt, err := NewNetworkType("QUIC", "REJECT")
	assert.NoError(t, err)
	assert.Equal(t, "quic", nt.Payload())
	assert.Equal(t, C.Network, nt.RuleType())

	// matched: sniffer confirmed QUIC
	m, adapter := nt.Match(&C.Metadata{NetWork: C.UDP, SniffProtocol: "quic"}, C.RuleMatchHelper{})
	assert.True(t, m)
	assert.Equal(t, "REJECT", adapter)

	// not matched: plain UDP (e.g. an Apple private protocol on port 443)
	m, _ = nt.Match(&C.Metadata{NetWork: C.UDP}, C.RuleMatchHelper{})
	assert.False(t, m)

	// not matched: TCP must not match even if the field is somehow set
	m, _ = nt.Match(&C.Metadata{NetWork: C.TCP, SniffProtocol: "quic"}, C.RuleMatchHelper{})
	assert.False(t, m)
}

func TestNetworkTypeQUICCaseInsensitive(t *testing.T) {
	for _, in := range []string{"QUIC", "quic", "QuIc"} {
		nt, err := NewNetworkType(in, "REJECT")
		assert.NoError(t, err)
		assert.Equal(t, "quic", nt.Payload())
	}
}

func TestNetworkTypeUDPStillWorks(t *testing.T) {
	nt, err := NewNetworkType("UDP", "REJECT")
	assert.NoError(t, err)

	m, _ := nt.Match(&C.Metadata{NetWork: C.UDP}, C.RuleMatchHelper{})
	assert.True(t, m)

	// regression: a QUIC-labelled UDP connection still matches NETWORK,UDP
	m, _ = nt.Match(&C.Metadata{NetWork: C.UDP, SniffProtocol: "quic"}, C.RuleMatchHelper{})
	assert.True(t, m)

	// TCP must not match UDP
	m, _ = nt.Match(&C.Metadata{NetWork: C.TCP}, C.RuleMatchHelper{})
	assert.False(t, m)
}

func TestNetworkTypeTCPStillWorks(t *testing.T) {
	nt, err := NewNetworkType("TCP", "DIRECT")
	assert.NoError(t, err)

	m, _ := nt.Match(&C.Metadata{NetWork: C.TCP}, C.RuleMatchHelper{})
	assert.True(t, m)

	m, _ = nt.Match(&C.Metadata{NetWork: C.UDP}, C.RuleMatchHelper{})
	assert.False(t, m)
}

func TestNetworkTypeInvalid(t *testing.T) {
	for _, in := range []string{"SCTP", "ALL", "", "IP"} {
		_, err := NewNetworkType(in, "REJECT")
		assert.Error(t, err, "network type %q should be rejected", in)
	}
}
