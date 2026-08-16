package cachefile

import (
	"strconv"
	"sync"

	"github.com/metacubex/bbolt"
)

var (
	poolPortInitOnce    sync.Once
	poolPortStore       *ProxyPortPoolStore
	bucketProxyPortPool = []byte("proxy_port_pool")
)

// ProxyPortPoolStore persists the proxy-name -> mixed-port mapping
// (proxy-port-pool feature) in the shared cache.db, same as fakeip.
type ProxyPortPoolStore struct {
	db *bbolt.DB
}

// GetProxyPortPoolStore returns the singleton store backed by cache.db.
func GetProxyPortPoolStore() *ProxyPortPoolStore {
	poolPortInitOnce.Do(func() {
		c := Cache()
		if c == nil || c.DB == nil {
			poolPortStore = &ProxyPortPoolStore{}
			return
		}

		err := c.DB.Update(func(tx *bbolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists(bucketProxyPortPool)
			return err
		})

		if err != nil {
			poolPortStore = &ProxyPortPoolStore{}
			return
		}
		poolPortStore = &ProxyPortPoolStore{db: c.DB}
	})

	return poolPortStore
}

// PutPort saves the port for a proxy name.
func (s *ProxyPortPoolStore) PutPort(name string, port int) {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Batch(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketProxyPortPool)
		if b == nil {
			return nil
		}
		return b.Put([]byte(name), []byte(strconv.Itoa(port)))
	})
}

// RemovePort deletes the mapping of a proxy name (node gone / manual listener).
func (s *ProxyPortPoolStore) RemovePort(name string) {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Batch(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketProxyPortPool)
		if b == nil {
			return nil
		}
		return b.Delete([]byte(name))
	})
}

// AllPorts returns a snapshot of the full name -> port mapping.
func (s *ProxyPortPoolStore) AllPorts() map[string]int {
	mapping := map[string]int{}
	if s == nil || s.db == nil {
		return mapping
	}
	_ = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketProxyPortPool)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if port, err := strconv.Atoi(string(v)); err == nil {
				mapping[string(k)] = port
			}
		}
		return nil
	})
	return mapping
}
