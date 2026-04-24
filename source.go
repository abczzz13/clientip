package clientip

import (
	"encoding/json"
	"errors"
	"net/textproto"
	"strings"
)

type sourceKind uint8

const (
	sourceInvalid sourceKind = iota
	sourceForwarded
	sourceXForwardedFor
	sourceXRealIP
	sourceRemoteAddr
	sourceStaticFallback
	sourceHeader
)

const (
	builtinSourceNameForwarded      = "forwarded"
	builtinSourceNameXForwardedFor  = "x_forwarded_for"
	builtinSourceNameXRealIP        = "x_real_ip"
	builtinSourceNameRemoteAddr     = "remote_addr"
	builtinSourceNameStaticFallback = "static_fallback"
)

// Exported source identifiers for comparison and display.
//
// These are vars because Go does not support const structs. Do not reassign
// them; internal code uses builtinSource() so reassignment would only affect
// caller-side comparisons, not extraction behavior.
var (
	// SourceForwarded resolves from the RFC7239 Forwarded header.
	SourceForwarded = Source{kind: sourceForwarded}
	// SourceXForwardedFor resolves from the X-Forwarded-For header.
	SourceXForwardedFor = Source{kind: sourceXForwardedFor}
	// SourceXRealIP resolves from the X-Real-IP header.
	SourceXRealIP = Source{kind: sourceXRealIP}
	// SourceRemoteAddr resolves from Request.RemoteAddr.
	SourceRemoteAddr = Source{kind: sourceRemoteAddr}
	// SourceStaticFallback identifies resolver-only static fallback output.
	SourceStaticFallback = Source{kind: sourceStaticFallback}
)

// Source identifies one extraction source in priority order.
//
// Use built-in constants for standard sources and HeaderSource for custom
// headers.
type Source struct {
	kind       sourceKind
	headerName string
}

func builtinSource(kind sourceKind) Source {
	return Source{kind: kind}
}

// HeaderSource returns a source backed by a custom HTTP header name.
func HeaderSource(name string) Source {
	return sourceFromString(name)
}

func canonicalSource(source Source) Source {
	switch source.kind {
	case sourceForwarded, sourceXForwardedFor, sourceXRealIP, sourceRemoteAddr, sourceStaticFallback:
		return source
	case sourceHeader:
		return sourceFromString(source.headerName)
	default:
		return Source{}
	}
}

func sourceFromString(name string) Source {
	// Fast path: check exact matches before trimming/normalizing.
	// Internal round-trips always use already-normalized names without whitespace.
	if s, ok := sourceFromExact(name); ok {
		return s
	}

	raw := strings.TrimSpace(name)
	if raw == "" {
		return Source{}
	}

	switch normalizeSourceName(raw) {
	case builtinSourceNameForwarded:
		return builtinSource(sourceForwarded)
	case builtinSourceNameXForwardedFor:
		return builtinSource(sourceXForwardedFor)
	case builtinSourceNameXRealIP:
		return builtinSource(sourceXRealIP)
	case builtinSourceNameRemoteAddr:
		return builtinSource(sourceRemoteAddr)
	case builtinSourceNameStaticFallback:
		return builtinSource(sourceStaticFallback)
	default:
		return Source{kind: sourceHeader, headerName: textproto.CanonicalMIMEHeaderKey(raw)}
	}
}

func sourceFromExact(name string) (Source, bool) {
	switch name {
	case builtinSourceNameForwarded, "Forwarded":
		return builtinSource(sourceForwarded), true
	case builtinSourceNameXForwardedFor, "X-Forwarded-For":
		return builtinSource(sourceXForwardedFor), true
	case builtinSourceNameXRealIP, "X-Real-Ip", "X-Real-IP":
		return builtinSource(sourceXRealIP), true
	case builtinSourceNameRemoteAddr:
		return builtinSource(sourceRemoteAddr), true
	case builtinSourceNameStaticFallback:
		return builtinSource(sourceStaticFallback), true
	default:
		return Source{}, false
	}
}

// canonicalizeSources ensures every source is in canonical form.
//
// Sources stored in config.sourcePriority are always canonical; callers must
// not rely on name()/valid()/headerKey() re-canonicalizing on each call.
func canonicalizeSources(sources []Source) []Source {
	resolved := make([]Source, len(sources))
	for i, source := range sources {
		resolved[i] = canonicalSource(source)
	}
	return resolved
}

func (s Source) String() string {
	return s.name()
}

// Equal reports whether two sources represent the same canonical source.
func (s Source) Equal(other Source) bool {
	return canonicalSource(s) == canonicalSource(other)
}

func (s Source) name() string {
	switch s.kind {
	case sourceForwarded:
		return builtinSourceNameForwarded
	case sourceXForwardedFor:
		return builtinSourceNameXForwardedFor
	case sourceXRealIP:
		return builtinSourceNameXRealIP
	case sourceRemoteAddr:
		return builtinSourceNameRemoteAddr
	case sourceStaticFallback:
		return builtinSourceNameStaticFallback
	case sourceHeader:
		return normalizeSourceName(s.headerName)
	default:
		return ""
	}
}

func (s Source) valid() bool {
	if s.kind == sourceHeader {
		return s.headerName != ""
	}

	return s.kind == sourceForwarded ||
		s.kind == sourceXForwardedFor ||
		s.kind == sourceXRealIP ||
		s.kind == sourceRemoteAddr ||
		s.kind == sourceStaticFallback
}

func (s Source) headerKey() (string, bool) {
	switch s.kind {
	case sourceForwarded:
		return "Forwarded", true
	case sourceXForwardedFor:
		return "X-Forwarded-For", true
	case sourceXRealIP:
		return "X-Real-IP", true
	case sourceRemoteAddr, sourceStaticFallback, sourceInvalid:
		return "", false
	default:
		return s.headerName, true
	}
}

func (s Source) marshalValue() string {
	if s.kind == sourceHeader {
		return s.headerName
	}

	return s.String()
}

// MarshalText returns a stable text form for the source.
//
// Built-in sources serialize as canonical identifiers. Custom header sources
// serialize as canonical MIME header names so they can be losslessly parsed.
func (s Source) MarshalText() ([]byte, error) {
	return []byte(s.marshalValue()), nil
}

// UnmarshalText parses a source from a built-in alias or header name.
func (s *Source) UnmarshalText(text []byte) error {
	if s == nil {
		return errors.New("clientip.Source: UnmarshalText on nil pointer")
	}

	*s = sourceFromString(string(text))
	return nil
}

// MarshalJSON returns the source as a JSON string.
func (s Source) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.marshalValue())
}

// UnmarshalJSON parses a source from a JSON string.
func (s *Source) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("clientip.Source: UnmarshalJSON on nil pointer")
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*s = sourceFromString(raw)
	return nil
}

func normalizeSourceName(headerName string) string {
	return strings.ToLower(strings.ReplaceAll(headerName, "-", "_"))
}

func sourceHeaderKeys(sourcePriority []Source) []string {
	keys := make([]string, 0, len(sourcePriority))
	seen := make(map[string]struct{}, len(sourcePriority))

	for _, source := range sourcePriority {
		key, ok := sourceHeaderKey(source)
		if !ok {
			continue
		}

		if _, duplicate := seen[key]; duplicate {
			continue
		}

		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	return keys
}

func sourceHeaderKey(source Source) (string, bool) {
	source = canonicalSource(source)
	if !source.valid() {
		return "", false
	}

	key, ok := source.headerKey()
	if !ok {
		return "", false
	}

	return key, true
}
