package picosession

import (
	"context"
	"net/http"
)

type sessionContextKey string

func (br *Broker) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// get session, if one exists
		_, err := r.Cookie("picosession")
		if err != nil {
			// create new session, and assign it to request context
			s := br.NewSession()
			ctx := context.WithValue(r.Context(), sessionContextKey("session"), s)
			r = r.WithContext(ctx)
			h.ServeHTTP(w, r)
			return
		}

		h.ServeHTTP(w, r)
	})
}
