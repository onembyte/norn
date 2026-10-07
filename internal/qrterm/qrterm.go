// Package qrterm draws a QR code in a terminal.
//
// A flow that needs a second device goes through a phone camera and a QR
// (§16.2): an enrollment request is ~250 characters, which nobody types
// across a room correctly.
//
// The encoding is rsc.io/qr's; what this package owns is the part a library
// cannot check -- the quiet zone and the light/dark mapping. A code with no
// quiet zone, or with its modules inverted, is a perfectly valid QR that no
// scanner will read, and the only test that would catch it in the field is a
// phone. So the matrix is built separately from the drawing and checked against
// the library's own module map.
package qrterm

import (
	"strings"

	"rsc.io/qr"
)

// QuietZone is the margin of light modules the standard requires on each side.
const QuietZone = 4

// ANSI colours, four-bit so that every terminal in use understands them.
// Explicit colours matter: half-blocks alone would invert on a light-background
// terminal and stop scanning.
const (
	reset      = "\x1b[0m"
	lightOnTop = "\x1b[97m" // bright white foreground
	darkOnTop  = "\x1b[30m" // black foreground
	lightBelow = "\x1b[107m"
	darkBelow  = "\x1b[40m"
)

// upperHalf paints the top module with the foreground colour and the bottom
// module with the background colour, so one character carries two rows.
const upperHalf = "▀"

// Matrix returns the code's modules with a quiet zone, true meaning dark.
func Matrix(code *qr.Code, quiet int) [][]bool {
	size := code.Size + 2*quiet
	matrix := make([][]bool, size)
	for y := range matrix {
		matrix[y] = make([]bool, size)
		for x := range matrix[y] {
			inside := x >= quiet && x < quiet+code.Size && y >= quiet && y < quiet+code.Size
			matrix[y][x] = inside && code.Black(x-quiet, y-quiet)
		}
	}
	return matrix
}

// Render draws the code as half-block characters, two module rows per line.
func Render(code *qr.Code) string {
	matrix := Matrix(code, QuietZone)
	var out strings.Builder
	for y := 0; y < len(matrix); y += 2 {
		for x := range matrix[y] {
			top := matrix[y][x]
			bottom := y+1 < len(matrix) && matrix[y+1][x]
			if top {
				out.WriteString(darkOnTop)
			} else {
				out.WriteString(lightOnTop)
			}
			if bottom {
				out.WriteString(darkBelow)
			} else {
				out.WriteString(lightBelow)
			}
			out.WriteString(upperHalf)
		}
		out.WriteString(reset)
		out.WriteString("\n")
	}
	return out.String()
}

// Encode builds a code at error-correction level M and draws it.
//
// Level M tolerates about 15% damage, which is the level ordinary QR readers
// and printed codes are tuned for; a request is short enough that a higher
// level would only make the code bigger on screen.
func Encode(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	return Render(code), nil
}
