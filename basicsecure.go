package basicsecure

import (
	"fmt"
	"net/http"
	"strings"
)

// BasicSecure is middleware for secure headers.
// It wraps an http.Handler and returns and http.Handler.
type BasicSecure struct {
	Testing      bool
	AllowedHosts []string
}

// Handler wraps an http.Handler and sets secured headers in the http.ResponseWriter.
func (bs BasicSecure) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bs.Testing {
			// Redirect if needed.
			bs.httpsRedirect(w, r)
			// Check the allowed hosts if you're on the production site.
			e := bs.checkHost(r)
			if e != nil {
				bs.badHostHandler(w, r)
				return
			}
		}
		// Set headers.
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Add("X-Content-Type-Options", "nosniff")
		w.Header().Add("X-Frame-Options", "DENY")
		w.Header().Add("X-Xss-Protection", "1;mode=block")
		csp := "default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; " +
			"frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none';"
		w.Header().Add("Content-Security-Policy", csp)
		w.Header().Add("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func (bs BasicSecure) badHostHandler(w http.ResponseWriter, r *http.Request) {
	if len(bs.AllowedHosts) > 0 {
		goodHost := bs.AllowedHosts[0]
		http.Error(w, "This is a bad host. Try: "+goodHost, http.StatusInternalServerError)
	} else {
		http.Error(w, "This is a bad host.", http.StatusInternalServerError)
	}
}

func (bs BasicSecure) checkHost(r *http.Request) error {
	host := r.Host
	if len(bs.AllowedHosts) > 0 {
		isGoodHost := false
		for _, allowedHost := range bs.AllowedHosts {
			if strings.EqualFold(allowedHost, host) {
				isGoodHost = true
				break
			}
		}
		if !isGoodHost {
			return fmt.Errorf("bad host name %s", host)
		}
	}
	return nil
}

func (bs BasicSecure) httpsRedirect(w http.ResponseWriter, r *http.Request) {
	// This is designed to work in Heroku. The X-Forwarded-Proto header is set by them. It might not work on other services.
	// There's an error that seems to stem from Godaddy forwarding that adds random characters to the path.
	// Any attempt to access a page with http will route to r.host.
	// https://stackoverflow.com/questions/46307518/random-5-alpha-character-path-appended-to-requests
	protocol := r.Header.Get("X-Forwarded-Proto")
	if protocol != "https" {
		target := "https://" + r.Host // + r.URL.Path doesn't work. The path gets changed by godaddy for some reason.
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		return
	}
}
