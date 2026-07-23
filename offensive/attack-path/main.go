// Command attack-path analyzes attack paths in a scenario graph.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/example/attack-path/internal/analysis"
	"github.com/example/attack-path/internal/ingest"
	"github.com/example/attack-path/internal/path"
	"github.com/example/attack-path/internal/render"
)

func main() {
	scenario := flag.String("scenario", "examples/scenario.json", "path to scenario JSON")
	format := flag.String("format", "text", "output format: text | json | dot")
	maxDepth := flag.Int("maxdepth", 12, "max path depth")
	top := flag.Int("top", 5, "number of remediation recommendations")
	flag.Parse()

	g, desc, err := ingest.LoadFile(*scenario)
	if err != nil {
		log.Fatalf("load scenario: %v", err)
	}

	paths := path.FindPaths(g, *maxDepth)
	recs := analysis.Remediation(paths, *top)
	name := desc.Name
	if name == "" {
		name = *scenario
	}

	switch *format {
	case "json":
		fmt.Println(render.JSON(name, paths, recs))
	case "dot":
		fmt.Print(render.DOT(g, paths))
	default:
		fmt.Print(render.Text(name, paths, recs))
	}
	_ = os.Stdout
}
