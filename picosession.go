package picosession

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"golang.unexpl0.red/picosession/crypto"
)

// goroutine safe session struct
type Session struct {
	m       sync.RWMutex
	kvstore map[any]any
}

type Broker struct {
	sb crypto.SecretBox
}

func (s *Session) Get(k any) (v any, exists bool) {
	s.m.RLock()
	defer s.m.RUnlock()
	v, exists = s.kvstore[k]
	return
}

func (s *Session) Put(k, v string) {
	s.m.Lock()
	defer s.m.Unlock()
	s.kvstore[k] = v
	return
}

func New(key [crypto.KeySize]byte) Broker {
	sb := crypto.NewSecretBox(key)
	b := Broker{
		sb: sb,
	}

	return b
}

func (b *Broker) NewSession() *Session {
	m := make(map[any]any)

	s := Session{
		kvstore: m,
	}

	return &s
}

func (b *Broker) bakeCookie(s Session) http.Cookie {
	// this should never fail, as it is a map of Marshalers
	sessionJson, err := json.Marshal(s.kvstore)
	if err != nil {
		panic("Error marshaling kvstore!")
	}

	e := b.sb.Encrypt(sessionJson)

	c := http.Cookie{
		Name:     "session",
		Value:    b64.StdEncoding.EncodeToString(e),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	return c
}

func (b *Broker) digestCookie(c *http.Cookie) (*Session, error) {
	var kv map[any]any

	e, err := b64.StdEncoding.DecodeString(c.Value)
	if err != nil {
		return &Session{}, errors.New("Failed to digest cookie, incorrect encoding")
	}

	d, ok := b.sb.Decrypt(e)
	if !ok {
		return &Session{}, errors.New("Failed to digest cookie, error decrypting")
	}

	err = json.Unmarshal(d, &kv)
	if err != nil {
		return &Session{}, errors.New("Failed to digest cookie, error unmarshaling: " + err.Error())
	}

	s := Session{
		kvstore: kv,
	}

	return &s, nil
}
