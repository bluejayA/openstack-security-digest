// Package translate provides cached, best-effort translation of advisory text.
// Translation never fails the caller: on any error or when no translator is
// configured, the original text is returned unchanged.
package translate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"
)

// Translator turns text into the target language.
type Translator interface {
	Translate(ctx context.Context, text, lang string) (string, error)
}

// Cache stores translations keyed by (content hash, lang).
type Cache interface {
	GetTranslation(hash, lang string) (string, bool)
	SaveTranslation(hash, lang, text string) error
}

// Service is the cached translator the rest of the app uses.
type Service struct {
	t     Translator // nil → translation disabled
	cache Cache
}

// NewService wraps a Translator (may be nil) with a cache.
func NewService(t Translator, cache Cache) *Service {
	return &Service{t: t, cache: cache}
}

// Enabled reports whether a translator is configured.
func (s *Service) Enabled() bool { return s != nil && s.t != nil }

// To returns text translated to lang, using the cache. It returns the original
// text unchanged when translation is disabled, the text is blank, or any error
// occurs — callers never have to handle translation failures.
func (s *Service) To(ctx context.Context, text, lang string) string {
	if !s.Enabled() || strings.TrimSpace(text) == "" {
		return text
	}
	h := hashText(text)
	if cached, ok := s.cache.GetTranslation(h, lang); ok {
		return cached
	}
	out, err := s.t.Translate(ctx, text, lang)
	if err != nil {
		log.Printf("translate: %v (returning original)", err)
		return text
	}
	if strings.TrimSpace(out) == "" {
		return text
	}
	if err := s.cache.SaveTranslation(h, lang, out); err != nil {
		log.Printf("translate: cache save: %v", err)
	}
	return out
}

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
