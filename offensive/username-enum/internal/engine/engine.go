// Package engine runs username enumeration across a service catalog using
// a pluggable source, applying rate limiting and producing an aggregate
// report. The engine is pure: it takes a Source and a Catalog and never
// opens sockets itself, so tests can inject a mock.
package engine

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/Schildkrote/username-enum/internal/service"
	"github.com/Schildkrote/username-enum/internal/source"
)

// errEmptyUsername is returned when no username was supplied.
var errEmptyUsername = errors.New("username is required")

// Options configures a single enumeration run.
type Options struct {
	// MaxProbes caps total probes (0 = unlimited; enforced for the live
	// run-cap rule).
	MaxProbes int
	// Interval between probes to the same host (0 = no throttling;
	// defaults to 200ms for the http source in real mode).
	Interval time.Duration
	// OnProbe, if set, is called with every result (used by audit logging).
	OnProbe func(source.Result)
}

// RunResult is the aggregate of one enumeration.
type RunResult struct {
	Username string           `json:"username"`
	Source   string           `json:"source"`
	Total    int              `json:"total"`
	Found    int              `json:"found"`
	Hits     []source.Result  `json:"hits"`
	Results  []source.Result  `json:"results"`
	ByWeight map[int][]string `json:"by_weight"` // weight -> service names with hits
	Duration time.Duration    `json:"duration"`
}

// Run enumerates username across all services in catalog, using src.
func Run(ctx context.Context, catalog service.Catalog, src source.Source, username string, opts Options) (*RunResult, error) {
	if username == "" {
		return nil, errEmptyUsername
	}
	start := time.Now()
	res := &RunResult{
		Username: username,
		Source:   src.Name(),
		ByWeight: map[int][]string{},
	}
	var ticker *time.Ticker
	if opts.Interval > 0 {
		ticker = time.NewTicker(opts.Interval)
		defer ticker.Stop()
	}

	for _, svc := range catalog {
		if opts.MaxProbes > 0 && res.Total >= opts.MaxProbes {
			break
		}
		urlTmpl := svc.URL
		urlOut, err := service.BuildURL(urlTmpl, username)
		if err != nil {
			continue
		}
		select {
		case <-ctx.Done():
			res.Duration = time.Since(start)
			return res, ctx.Err()
		default:
		}
		if ticker != nil {
			<-ticker.C
		}
		r, err := src.Probe(ctx, svc.Name, urlOut, username)
		if err != nil {
			r.Uncertain = true
		}
		r.URL = urlOut
		res.Total++
		res.Results = append(res.Results, r)
		if r.Found {
			res.Found++
			res.Hits = append(res.Hits, r)
			res.ByWeight[svc.Weight] = append(res.ByWeight[svc.Weight], svc.Name)
		}
		if opts.OnProbe != nil {
			opts.OnProbe(r)
		}
	}
	sort.Slice(res.Results, func(i, j int) bool {
		if res.Results[i].Found != res.Results[j].Found {
			return res.Results[i].Found
		}
		return res.Results[i].Service < res.Results[j].Service
	})
	res.Duration = time.Since(start)
	return res, nil
}
