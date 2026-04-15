package clientip

import "strings"

type chainedSource struct {
	sources    []sourceExtractor
	sourceName string
	isTerminal func(error) bool
}

func newChainedSource(isTerminal func(error) bool, sources ...sourceExtractor) *chainedSource {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.name()
	}

	return &chainedSource{
		sources:    sources,
		sourceName: "chained[" + strings.Join(names, ",") + "]",
		isTerminal: isTerminal,
	}
}

func (c *chainedSource) extract(r requestView) (Extraction, error) {
	var lastErr error
	for i, source := range c.sources {
		// Context is already checked by extractWithSource before the first
		// source; only re-check between subsequent sources in the chain.
		if i > 0 {
			if err := r.context().Err(); err != nil {
				return Extraction{}, err
			}
		}

		result, err := source.extract(r)
		if err == nil {
			return result, nil
		}

		if c.isTerminal != nil && c.isTerminal(err) {
			return Extraction{}, err
		}

		lastErr = err
	}

	return Extraction{}, lastErr
}

func (c *chainedSource) name() string {
	return c.sourceName
}

func (c *chainedSource) sourceInfo() Source {
	return Source{}
}
