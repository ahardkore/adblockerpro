// Package web embeds the dashboard assets into the binary so the Pi needs
// nothing but the single executable.
package web

import "embed"

// FS holds the static dashboard files under "static/".
//
//go:embed static
var FS embed.FS
