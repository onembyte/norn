package docclaims

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The packet is what an operator reviews. Keep each claim under its own row
// and system, so a repeated "no" elsewhere cannot conceal a changed cell.
func TestEveryComparisonRowHasItsVerbatimClaimsInTheReviewPacket(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root(t), "REVIEW-COMPARISON.md"))
	if err != nil {
		t.Fatalf("read REVIEW-COMPARISON.md: %v", err)
	}
	_, table, ok := strings.Cut(readme(t), "## How Norn compares\n")
	if !ok {
		t.Fatal("README.md has no comparison section")
	}
	table, _, _ = strings.Cut(table, "\n## ")
	var rows [][]string
	for _, line := range strings.Split(table, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 7 {
			t.Fatalf("comparison row needs a question and four cells: %q", line)
		}
		row := cells[1:6]
		for i := range row {
			row[i] = strings.TrimSpace(row[i])
		}
		rows = append(rows, row)
	}
	if len(rows) < 3 {
		t.Fatal("README.md comparison table has no claims")
	}
	sections := strings.Split(string(raw), "\n## ")[1:]
	if len(sections) != len(rows)-2 {
		t.Fatalf("REVIEW-COMPARISON.md has %d row sections; README.md has %d", len(sections), len(rows)-2)
	}
	for i, row := range rows[2:] {
		question, body, _ := strings.Cut(sections[i], "\n")
		if question != row[0] {
			t.Errorf("comparison row %d question: want %q, got %q", i+1, row[0], question)
		}
		for j, claim := range row[1:] {
			system := strings.Trim(rows[0][j+1], "*")
			want := "- " + system + ": " + claim
			found := false
			for _, line := range strings.Split(body, "\n") {
				if line == want {
					found = true
				}
			}
			if !found {
				t.Errorf("comparison row %d missing verbatim cell %q", i+1, want)
			}
		}
	}
}
