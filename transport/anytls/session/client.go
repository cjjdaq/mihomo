package session

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/anytls/padding"
	"github.com/metacubex/mihomo/transport/anytls/skiplist"
	"github.com/metacubex/mihomo/transport/anytls/util"
)

type Client struct {
	die       context.Context
	dieCancel context.CancelFunc

	dialOut util.DialOutFunc

	sessionCounter atomic.Uint64

	idleSession     *skiplist.SkipList[uint64, *Session]
	idleSessionLock sync.Mutex

	sessions     map[uint64]*Session
	sessionsLock sync.Mutex

	// refilling 标记后台预热补满任务是否在运行，避免 cleanup 周期重叠时重复触发
	refilling atomic.Bool

	padding *atomic.Pointer[padding.PaddingFactory]

	clientMetadata     string
	idleSessionTimeout time.Duration
	minIdleSession     int
	disableReuse       bool

	// logName 用于在日志中标识所属 outbound 节点（可选，由上层注入）
	logName string
}

// SetLogName 由上层（如 transport/anytls.NewClient）调用，用于让 session 层日志带上节点名
func (c *Client) SetLogName(name string) {
	c.logName = name
}

func (c *Client) logPrefix() string {
	if c.logName != "" {
		return "[AnyTLS][" + c.logName + "]"
	}
	return "[AnyTLS]"
}

func NewClient(ctx context.Context, dialOut util.DialOutFunc, _padding *atomic.Pointer[padding.PaddingFactory], clientMetadata string, idleSessionCheckInterval, idleSessionTimeout time.Duration, minIdleSession int, disableReuse bool) *Client {
	c := &Client{
		sessions:           make(map[uint64]*Session),
		dialOut:            dialOut,
		padding:            _padding,
		clientMetadata:     clientMetadata,
		idleSessionTimeout: idleSessionTimeout,
		minIdleSession:     minIdleSession,
		disableReuse:       disableReuse,
	}
	if idleSessionCheckInterval <= time.Second*5 {
		idleSessionCheckInterval = time.Second * 30
	}
	if c.idleSessionTimeout <= time.Second*5 {
		c.idleSessionTimeout = time.Second * 30
	}
	c.die, c.dieCancel = context.WithCancel(ctx)
	c.idleSession = skiplist.NewSkipList[uint64, *Session]()
	if !c.disableReuse {
		util.StartRoutine(c.die, idleSessionCheckInterval, c.idleCleanup)
	}
	return c
}

// createStreamMaxAttempts OpenStream 失败（常见：tls: protocol is shutdown）时
// 废掉坏 session 并换池/新建的最大尝试次数。
// 预热池里可能积压已被对端掐掉但仍未从 idle 表摘除的半死 session，
// 单次尝试会直接把错误抛给上层；多试几次可在客户端侧自愈。
const createStreamMaxAttempts = 3

func (c *Client) CreateStream(ctx context.Context) (net.Conn, error) {
	select {
	case <-c.die.Done():
		return nil, io.ErrClosedPipe
	default:
	}

	var lastErr error
	for attempt := 1; attempt <= createStreamMaxAttempts; attempt++ {
		select {
		case <-c.die.Done():
			return nil, io.ErrClosedPipe
		case <-ctx.Done():
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, ctx.Err()
		default:
		}

		var session *Session
		var err error
		if !c.disableReuse {
			session = c.getIdleSession()
		}
		if session == nil {
			session, err = c.createSession(ctx)
			if session == nil {
				if err != nil {
					lastErr = fmt.Errorf("failed to create session: %w", err)
				} else {
					lastErr = fmt.Errorf("failed to create session")
				}
				// dial 失败也再试（瞬时拒连 / 超时），但不会无限重试
				continue
			}
		}

		stream, err := session.OpenStream()
		if err != nil {
			// 会话已死或写控制帧失败：关掉，避免半死 session 回池
			session.Close()
			lastErr = fmt.Errorf("failed to create stream: %w", err)
			log.Debugln("%s OpenStream failed seq=%d attempt=%d/%d: %v",
				c.logPrefix(), session.seq, attempt, createStreamMaxAttempts, err)
			// 池可能被掏空，异步补 min-idle
			if !c.disableReuse && c.minIdleSession > 0 {
				c.refillIdleSessions()
			}
			continue
		}

		// 闭包绑定本次成功的 session
		sess := session
		stream.dieHook = func() {
			// If Session is not closed, put this Stream to pool
			if !sess.IsClosed() {
				if c.disableReuse {
					sess.Close()
					return
				}

				select {
				case <-c.die.Done():
					// Now client has been closed
					sess.Close()
				default:
					c.idleSessionLock.Lock()
					sess.idleSince = time.Now()
					c.idleSession.Insert(math.MaxUint64-sess.seq, sess)
					c.idleSessionLock.Unlock()
				}
			}
		}

		if attempt > 1 {
			log.Debugln("%s CreateStream recovered after %d attempt(s) seq=%d",
				c.logPrefix(), attempt, sess.seq)
		}
		return stream, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("failed to create stream: exhausted %d attempts", createStreamMaxAttempts)
}

// getIdleSession 从空闲池取出一个仍存活的 session。
// 跳过已关闭的条目（对端掐 TLS / recvLoop 退出后可能短暂留在跳表里）。
func (c *Client) getIdleSession() (idle *Session) {
	c.idleSessionLock.Lock()
	for !c.idleSession.IsEmpty() {
		it := c.idleSession.Iterate()
		sess := it.Value()
		c.idleSession.Remove(it.Key())
		if sess != nil && !sess.IsClosed() {
			idle = sess
			break
		}
	}
	c.idleSessionLock.Unlock()
	return
}

func (c *Client) createSession(ctx context.Context) (*Session, error) {
	underlying, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	session := NewClientSession(underlying, c.padding, c.clientMetadata)
	session.seq = c.sessionCounter.Add(1)
	session.dieHook = func() {
		if !c.disableReuse {
			c.idleSessionLock.Lock()
			c.idleSession.Remove(math.MaxUint64 - session.seq)
			c.idleSessionLock.Unlock()
		}

		c.sessionsLock.Lock()
		delete(c.sessions, session.seq)
		c.sessionsLock.Unlock()
	}

	c.sessionsLock.Lock()
	c.sessions[session.seq] = session
	c.sessionsLock.Unlock()

	session.Run()
	return session, nil
}

func (c *Client) Close() error {
	c.dieCancel()

	c.sessionsLock.Lock()
	sessionToClose := make([]*Session, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessionToClose = append(sessionToClose, session)
	}
	c.sessions = make(map[uint64]*Session)
	c.sessionsLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}

	return nil
}

func (c *Client) idleCleanup() {
	c.idleCleanupExpTime(time.Now().Add(-c.idleSessionTimeout))

	// 输出当前 idle pool 状态便于排查
	if c.minIdleSession > 0 {
		c.idleSessionLock.Lock()
		cur := c.idleSession.Len()
		c.idleSessionLock.Unlock()
		log.Debugln("%s idle pool status: %d/%d", c.logPrefix(), cur, c.minIdleSession)
	}

	// 清理过后检查并按需补满空闲池：服务端主动断开 / 网络抖动 / session 内部错误
	// 都会让 idle 数量降到 minIdleSession 以下，单纯靠 idleCleanupExpTime 的"刷新过期时间"
	// 机制是补不回来的，需要主动重建会话。
	c.refillIdleSessions()
}

func (c *Client) idleCleanupExpTime(expTime time.Time) {
	activeCount := 0
	sessionToClose := make([]*Session, 0, c.idleSession.Len())

	c.idleSessionLock.Lock()
	it := c.idleSession.Iterate()
	for it.IsNotEnd() {
		session := it.Value()
		key := it.Key()
		it.MoveToNext()

		if !session.idleSince.Before(expTime) {
			activeCount++
			continue
		}

		if activeCount < c.minIdleSession {
			session.idleSince = time.Now()
			activeCount++
			continue
		}

		sessionToClose = append(sessionToClose, session)
		c.idleSession.Remove(key)
	}
	c.idleSessionLock.Unlock()

	for _, session := range sessionToClose {
		session.Close()
	}
}

// refillIdleSessions 异步补满空闲池到 minIdleSession 数量。
//
// 触发场景：
//   - idle pool 中的 session 因服务端主动关闭/网络抖动/内部错误等原因从池中消失
//   - 这些场景下 dieHook 只把 session 从池中删除，不会自动重建
//
// 实现要点：
//   - 通过 refilling atomic.Bool CAS 防止上一轮还没完下一轮又开始
//   - 失败立即停止本轮，等下一个 cleanup 周期再试，避免不可达节点上的 busy loop
//   - 每次建立间隔 200ms 防止瞬时握手突发
func (c *Client) refillIdleSessions() {
	if c.disableReuse || c.minIdleSession <= 0 {
		return
	}
	if !c.refilling.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer c.refilling.Store(false)
		const (
			dialTimeout       = 8 * time.Second
			perSessionDelayMs = 200
		)

		// 进入前先快速探测：是否已满？满则不打日志，避免冗余
		c.idleSessionLock.Lock()
		curStart := c.idleSession.Len()
		c.idleSessionLock.Unlock()
		if curStart >= c.minIdleSession {
			return
		}

		log.Debugln("%s refilling idle pool: %d/%d, need %d more",
			c.logPrefix(), curStart, c.minIdleSession, c.minIdleSession-curStart)

		built := 0
		for {
			select {
			case <-c.die.Done():
				return
			default:
			}

			c.idleSessionLock.Lock()
			cur := c.idleSession.Len()
			c.idleSessionLock.Unlock()
			if cur >= c.minIdleSession {
				log.Debugln("%s refill done: built=%d, idle=%d/%d",
					c.logPrefix(), built, cur, c.minIdleSession)
				return
			}

			ctx, cancel := context.WithTimeout(c.die, dialTimeout)
			session, err := c.createSession(ctx)
			cancel()
			if err != nil {
				log.Debugln("%s refill failed: built=%d, idle=%d/%d, err=%v",
					c.logPrefix(), built, cur, c.minIdleSession, err)
				return
			}

			// 直接放入空闲池（模拟 stream.dieHook 的行为）
			c.idleSessionLock.Lock()
			session.idleSince = time.Now()
			c.idleSession.Insert(math.MaxUint64-session.seq, session)
			c.idleSessionLock.Unlock()
			built++
			log.Debugln("%s refill session ok: built=%d/%d",
				c.logPrefix(), built, c.minIdleSession-curStart)

			select {
			case <-c.die.Done():
				return
			case <-time.After(perSessionDelayMs * time.Millisecond):
			}
		}
	}()
}
