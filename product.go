// SPDX-License-Identifier: AGPL-3.0-only

// Package product embeds the canonical project identity and license so the
// installed binary can expose them without a source checkout or network access.
package product

import _ "embed"

// LicenseText is the complete, unmodified GNU AGPL version 3 license document.
//
//go:embed LICENSE
var LicenseText string

// Metadata is the public developer, source and license information.
//
//go:embed project.json
var Metadata []byte
