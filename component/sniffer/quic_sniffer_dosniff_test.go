package sniffer

import (
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubPacketSender satisfies constant.PacketSender with no-op behaviour so
// DoSniff can be exercised without a real tunnel attachment.
type stubPacketSender struct{}

func (stubPacketSender) Close()                                 {}
func (stubPacketSender) Send(C.PacketAdapter)                   {}
func (stubPacketSender) Process(C.PacketConn, C.WriteBackProxy) {}
func (stubPacketSender) DoSniff(*C.Metadata) error              { return nil }
func (stubPacketSender) AddMapping(*C.Metadata, *C.Metadata)    {}
func (stubPacketSender) RestoreReadFrom(addr netip.Addr) netip.Addr {
	return addr
}

// newTestQuicSender builds a quicPacketSender with only the fields DoSniff
// touches, which keeps the test independent of the packet parsing machinery.
func newTestQuicSender() *quicPacketSender {
	return &quicPacketSender{
		done:         make(chan struct{}),
		PacketSender: stubPacketSender{},
	}
}

func TestQuicDoSniffWritesProtocolOnDone(t *testing.T) {
	q := newTestQuicSender()
	q.isQUIC = true
	close(q.done) // the wrapper finished sniffing before DoSniff was called

	meta := &C.Metadata{NetWork: C.UDP}
	require.NoError(t, q.DoSniff(meta))

	assert.Equal(t, ProtocolQUIC, meta.SniffProtocol)
}

// This is the branch that regressed first when the flag was only read on the
// done path: a confirmed QUIC flow whose SNI was never assembled reaches the
// timeout branch with q.result empty and must still be labelled.
func TestQuicDoSniffWritesProtocolOnTimeout(t *testing.T) {
	q := newTestQuicSender()
	q.isQUIC = true
	// done is never closed, so DoSniff blocks until quicWaitConn elapses.
	// keep the wait short for the test by closing the channel right after.
	go func() {
		time.Sleep(10 * time.Millisecond)
		q.close()
	}()

	meta := &C.Metadata{NetWork: C.UDP}
	require.NoError(t, q.DoSniff(meta))

	assert.Equal(t, ProtocolQUIC, meta.SniffProtocol)
}

func TestQuicDoSniffLeavesProtocolEmptyForNonQUIC(t *testing.T) {
	q := newTestQuicSender()
	// isQUIC stays false: the datagram never passed the version whitelist.
	close(q.done)

	meta := &C.Metadata{NetWork: C.UDP}
	require.NoError(t, q.DoSniff(meta))

	assert.Empty(t, meta.SniffProtocol, "a non-QUIC flow must not be labelled")
}

func TestQuicDoSniffKeepsSniffHostBehaviour(t *testing.T) {
	q := newTestQuicSender()
	q.isQUIC = true
	q.result = "example.com"
	q.replaceDomain = func(metadata *C.Metadata, host string) {
		metadata.SniffHost = host
	}
	close(q.done)

	meta := &C.Metadata{NetWork: C.UDP}
	require.NoError(t, q.DoSniff(meta))

	assert.Equal(t, "example.com", meta.SniffHost)
	assert.Equal(t, ProtocolQUIC, meta.SniffProtocol)
}

// A datagram that stops being well-formed before the end must not latch the
// flag, otherwise private protocols that merely start with a QUIC version
// number would be classified as QUIC.
func TestReadQUICDataDoesNotLatchOnMalformedPacket(t *testing.T) {
	q := newTestQuicSender()
	t.Cleanup(q.close)

	// Long header form (0xC0) + QUIC v1 version, then nothing else: the
	// connection ID and length fields are missing, so parsing fails after the
	// version check.
	malformed := []byte{0xC0, 0x00, 0x00, 0x00, 0x01}

	require.Error(t, q.readQUICData(malformed))
	assert.False(t, q.isQUIC, "a malformed datagram must not be latched as QUIC")
}

func TestProtocolQUICConstantMatchesRuleSide(t *testing.T) {
	// The rule layer matches on this exact string; guard against an accidental
	// rename silently breaking NETWORK,quic.
	assert.Equal(t, "quic", ProtocolQUIC)
}
