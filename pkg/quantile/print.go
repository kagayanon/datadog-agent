package quantile

import (
	"fmt"
	"io"
	"strings"

	humanize "github.com/dustin/go-humanize"
)

const (
	// defaultBinPerLine controls how many bins we print per line.
	defaultBinPerLine = 32
)

type memSized interface {
	// MemSize returns memory use in bytes:
	//   used: uses len(bins)
	//   allocated: uses cap(bins)
	MemSize() (used, allocated int)
}

// printBins pretty prints bins to w.
//
// output:
// 	<k>:<n>...
func printBins(w io.Writer, bins []bin, maxPerLine int) {
	for i, b := range bins {
		prefix := ""

		if i != 0 {
			prefix = " "
			if maxPerLine > 0 && i%maxPerLine == 0 {
				prefix = "\n"
			}
		}

		fmt.Fprintf(w, "%s%d:%d", prefix, b.k, b.n)
		i++
	}
}

func printSketch(w io.Writer, s *Sketch, c *Config) {
	fmt.Fprintln(w, "sketch:")
	head := func(s string) {
		fmt.Fprintln(w, indent(s, 1))
	}

	iprintf := func(format string, a ...interface{}) {
		fmt.Fprintf(w, indent(format, 2), a...)
	}

	// bins
	head("bins:")
	fmt.Fprintln(w, indent(s.bins.String(), 2))

	// size
	head("size:")
	used, allocated := s.MemSize()
	iprintf("used=%s allocated=%s %3.2f%%",
		humanize.Bytes(uint64(used)),
		humanize.Bytes(uint64(allocated)),
		float64(used)/float64(allocated)*100,
	)
	fmt.Fprint(w, "\n")
	iprintf("len=%d cap=%d", len(s.bins), cap(s.bins))
	fmt.Fprint(w, "\n")

	// stats
	head("stats:")
	fmt.Fprint(w, "    ")
	for i, p := range []float64{1, 50, 75, 90, 95, 99} {
		if i != 0 {
			fmt.Fprint(w, " ")
		}
		fmt.Fprintf(w, "%02g=%.2f", p, s.Quantile(c, p/100))
	}
	fmt.Fprint(w, "\n")
	fmt.Fprintln(w, indent(s.Basic.String(), 2))
}

func indent(s string, level int) string {
	// TODO: this is bad
	space := strings.Repeat(" ", 2*level)
	out := strings.Replace(s, "\n", "\n"+space, -1)
	return space + strings.TrimSpace(out)
}
