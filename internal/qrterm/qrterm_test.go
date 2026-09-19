package qrterm

import (
	"strings"
	"testing"

	"rsc.io/qr"
)

func encode(t *testing.T, text string) *qr.Code {
	t.Helper()
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// The matrix is the part Norn owns: the library says which modules are black,
// and this package decides what a terminal shows. A wrong quiet zone or an
// inverted module is a code that simply does not scan, and no unit test of the
// library would catch it.
func TestMatrixMirrorsTheCode(t *testing.T) {
	code := encode(t, "NORN1TESTPAYLOAD")
	matrix := Matrix(code, QuietZone)

	want := code.Size + 2*QuietZone
	if len(matrix) != want {
		t.Fatalf("matrix is %d rows, want %d", len(matrix), want)
	}
	for y, row := range matrix {
		if len(row) != want {
			t.Fatalf("row %d is %d wide, want %d", y, len(row), want)
		}
		for x, dark := range row {
			inside := x >= QuietZone && x < QuietZone+code.Size &&
				y >= QuietZone && y < QuietZone+code.Size
			expected := inside && code.Black(x-QuietZone, y-QuietZone)
			if dark != expected {
				t.Fatalf("module (%d,%d) = %v, want %v", x, y, dark, expected)
			}
		}
	}
}

// Four light modules on every side, or a scanner cannot find the code. This is
// the classic reason a terminal QR fails in the field.
func TestQuietZoneIsPresentOnEverySide(t *testing.T) {
	if QuietZone < 4 {
		t.Fatalf("QuietZone = %d, and the standard requires 4", QuietZone)
	}
	matrix := Matrix(encode(t, "NORN1QUIETZONE"), QuietZone)
	size := len(matrix)
	for i := 0; i < size; i++ {
		for band := 0; band < QuietZone; band++ {
			for _, dark := range []bool{
				matrix[band][i], matrix[size-1-band][i],
				matrix[i][band], matrix[i][size-1-band],
			} {
				if dark {
					t.Fatalf("a dark module inside the quiet zone, band %d", band)
				}
			}
		}
	}
}

func TestRenderIsTwoRowsPerLine(t *testing.T) {
	code := encode(t, "NORN1RENDER")
	matrix := Matrix(code, QuietZone)
	lines := strings.Split(strings.TrimSuffix(Render(code), "\n"), "\n")

	want := (len(matrix) + 1) / 2
	if len(lines) != want {
		t.Fatalf("%d lines, want %d: half-block rendering puts two module rows on one line",
			len(lines), want)
	}
	for i, line := range lines {
		if !strings.HasSuffix(line, reset) {
			t.Fatalf("line %d does not reset the terminal's colours", i)
		}
	}
}

// §16.2 permits an uppercase request precisely because QR alphanumeric mode has
// no lowercase letters. If that were not true the allowance would be pointless,
// so it is measured rather than assumed.
func TestUppercasePaysForItself(t *testing.T) {
	const payload = "norn1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	lower := encode(t, payload)
	upper := encode(t, strings.ToUpper(payload))
	if upper.Size >= lower.Size {
		t.Errorf("uppercase is %d modules and lowercase %d: alphanumeric mode did not help",
			upper.Size, lower.Size)
	}
}

func TestRenderIsStableForTheSamePayload(t *testing.T) {
	first := Render(encode(t, "NORN1STABLE"))
	second := Render(encode(t, "NORN1STABLE"))
	if first != second {
		t.Error("the same request rendered differently twice")
	}
}
