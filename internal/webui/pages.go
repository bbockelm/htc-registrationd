package webui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/style.css
var styleCSS []byte

// pageNames are the templates rendered inside layout.html.
var pageNames = []string{"enter_code", "approve", "message", "registrations"}

type pages struct {
	t map[string]*template.Template
}

func loadPages() (*pages, error) {
	funcs := template.FuncMap{
		"utc": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		},
	}
	p := &pages{t: map[string]*template.Template{}}
	for _, name := range pageNames {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("webui: parsing %s: %w", name, err)
		}
		p.t[name] = t
	}
	return p, nil
}

// base is what every page shows: the signed-in user and the CSRF token
// for the sign-out form.
type base struct {
	Title   string
	User    *session
	IsAdmin bool
	CSRF    string
}

// messagePage is a heading, a statement and an optional link.
type messagePage struct {
	base
	Heading  string
	Text     string
	Detail   string
	LinkHref string
	LinkText string
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.pages.t[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("webui: rendering page", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, heading, text string) {
	s.render(w, status, "message", messagePage{base: s.base(r, heading), Heading: heading, Text: text})
}

func serveStyle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(styleCSS)
}
