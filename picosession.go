package picosession


import(
	"encoding/json"
	b64 "encoding/base64"
	"golang.unexpl0.red/picosession/crypto"
)

type Session struct {
	m sync.Mutex
	kvstore map[string]json.Marshaler
}


type Broker struct {
	sb crypto.SecretBox
}

func (s *Session) Get(k string) (v string, exists bool) {
	s.m.RLock()
	defer s.m.RUnlock()
	v, exists := s.kvstore[k]
	return
}

func(s *Session) Put(k, v string) {
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
	m := make(map[string]json.Marshaler)

	s := &Session{
		kvstore: m
	}

	return s
}

func (b *Broker) BakeCookie(s *Session) http.Cookie {
	//this should never fail, as it is a map of Marshalers
	sessionJson, err := json.Marshal(s.kvstore)
	if err != nil {
		panic("Error marshaling kvstore!")
	}

	e := b.sb.Encrypt(sessionJson)

	c := http.Cookie{
		Name: "session",
		Value: b64.EncodeToString(e),
		HttpOnly: true,
		Secure:   true,
	}
	return c
}

func(b *Broker) DigestCookie(c *http.Cookie) (Session, err) {
	var kv map[string]json.Marshaler

	e, err := b64.DecodeString(c.Value)
	if err != nil {
		return errors.New("Failed to digest cookie, incorrect encoding")
	}

	d, ok := b.sb.Decrypt(e)
	if !ok {
		return errors.New("Failed to digest cookie, error decrypting")
	}

	err := json.Unmarshal(d, &kv)

	if err != nil {
		return errors.New("Failed to digest cookie, error unmarshaling: " + err.Errori())
	}

	s := Session{
		kvstore: kv,
	}

	return s
}



