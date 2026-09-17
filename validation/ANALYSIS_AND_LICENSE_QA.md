# Analysis enhancements and developer attribution — QA

Date: 2026-09-15

## Design assessment

The existing portal already had a coherent dark/light token system, working authentication, aggregate APIs, Flow Lens filters, URL state and an operational navigation shell. These were preserved.

The main analytical gaps were the absence of dedicated change/bandwidth analysis and the lack of usable endpoint/conversation views despite existing storage APIs. Endpoint and conversation APIs ignored the shared flow predicates. Sparse timelines connected separated samples across long gaps, implying continuous traffic. Developer attribution was absent and the project still declared Apache licensing.

## Design system and navigation

The new views reuse slate surfaces, subtle borders, compact typography, tabular numbers, existing focus states and neutral teal/blue analytical colors. No framework, chart library or animation dependency was introduced. Tables and comparison rulers carry the primary information; there is no additional wall of KPI cards.

- Analytics → Workspace, Traffic changes, Bandwidth.
- Traffic → Breakdown, Endpoints, Conversations.
- Existing application/protocol/country/ASN/interface tabs remain within Breakdown.
- System, sidebar footer and login screen now expose About & license.
- Overview, Executive, Flow Explorer, Traffic Matrix, Exporters and Reports retain their primary navigation positions.

## Page improvements

- **Traffic changes:** neutral absolute/percentage comparisons, largest contributor changes first, dimension/metric selection, compact aligned period overlay, accurate treatment of missing Top-50 entries.
- **Bandwidth:** average, P95 and peak interval rates, rate distribution, complete-bucket sample counts and busiest-period drill-down.
- **Endpoints:** server ranking by bytes/packets/flows/unique peers, sent/received totals, shared filters, IP profiles and bounded CSV export.
- **Conversations:** canonical endpoint/port pairs, both traffic directions, server ranking, shared filters and exact directional flow queries where supported.
- **Overview / Executive / Analytics / Traffic:** missing timeline buckets are filled instead of connecting distant samples with a misleading slope. Completely empty periods retain their no-data state. Compact analytical charts use fewer axis ticks.
- **IP Detail:** server totals honor the shared lens, selecting an IP replaces the previous Either IP condition, and missing timeline buckets are filled. Other filters remain in force.
- **System:** added About & license to its existing tabs. Ingestion/storage controls retain their behavior.
- **Flow Explorer / Matrix / Exporters / Reports:** existing screens were visually checked. Their existing APIs remain in use; the new analyses open Flow Explorer using supported predicates and the selected period.

Removed redundant sidebar copies of Traffic category links; the existing in-page category tabs remain. Removed the Apache project declaration and misleading interpolation through absent aggregate buckets.

## Developer and license

Developer information is maintained in `project.json`: Cuma KURT, cumakurt@gmail.com, the supplied LinkedIn profile and GitHub source repository.

The project declares **AGPL-3.0-only**. `LICENSE` contains the full GNU AGPL v3 text from the SPDX license data; `NOTICE` identifies the project, developer and version-only license choice. The binary embeds both project metadata and the license. Public `GET /api/v1/about` and `GET /LICENSE` work before sign-in without exposing telemetry/configuration.

Updated README, changelog, Debian maintainer/homepage/notices, RPM packager/URL/license/notices, SPDX and CycloneDX package metadata. The standard SPDX document-level CC0 data license remains distinct from the application's AGPL license.

Validated artifacts have been copied to `dist/`: ten Linux binaries, two Debian packages, one x86_64 RPM, license/notices and refreshed SBOM/checksum files. Previous artifacts are backed up at `/tmp/cfc-insights.abPUjO/dist-before`. No production service was restarted.

## Performance and accessibility

- Embedded frontend assets increased from 139,593 to 168,729 bytes: **29,136 bytes added**, measured without compression.
- One comparison response supplies all dimension/metric redraws; the browser test verifies no additional comparison request for those control changes.
- Endpoint/conversation ranking happens before the server result limit. The portal renders at most 100 records; comparison unions at most 100 contributors and peak lists contain at most 10 intervals.
- Timeline generation is bounded and uses one SVG path per series. No new periodic poller was added. About metadata is fetched on demand.
- Requests retain route cancellation/timeouts. A failed analytical range leaves time/filter controls available for recovery.
- Labels, semantic buttons/links, sticky table headers, numeric signs/status text and keyboard chart controls remain available. The About dialog supports link focus, Tab wrapping, Escape and focus restoration. CSV text is escaped and spreadsheet formula prefixes are neutralized.

## Tests executed

Passed:

- `go test ./...`
- `go vet ./...`
- `go test -race ./internal/api ./internal/storage`
- `node --check` for every embedded JavaScript file.
- `node scripts/ui/state.test.cjs` — 7 tests.
- `node scripts/ui/insight-state.test.cjs` — 8 tests.
- `scripts/ui/insights-interactions.cjs` — 17 browser workflow checks, zero JavaScript exceptions.
- `scripts/build-static.sh` — all five tools for Linux amd64 and arm64.
- `scripts/build-deb.sh` — amd64 and arm64 packages; extracted license bytes and maintainer metadata verified.
- `scripts/build-rpm.sh` — x86_64 package; license, packager, source URL and packaged notices verified.
- Shell syntax checks for modified packaging scripts, OpenAPI YAML/parameter reference checks and SBOM attribution/license checks.
- Both `dist/checksums.txt` and `dist/static-checksums.txt` verified with `sha256sum -c`.

New backend tests exercise filters before aggregation, both conversation directions, sorting before limiting, host/peer lens separation, duration predicates, cancellation, invalid input, HTTP handler integration, SQL parameterization and public embedded license delivery.

Browser testing used an isolated local collector with 22,000 previously decoded NetFlow test records. No API response interception or fabricated telemetry was used for functional or visual review.

## Screens and visual regression

Captured dark/light screens at **2560×1440, 1920×1080, 1440×900 and 1366×768**:

- 104 baseline screenshots of the existing portal.
- 104 final screenshots of the same portal routes.
- 32 final screenshots of the four new analytical views.
- 8 screenshots of the About dialog.

Final capture audits report **zero browser errors, zero failed telemetry API responses, zero error panels and zero horizontal page overflows**. The expected unauthenticated initial `/auth/me` response is excluded from API-failure counts.

Compared 104 matching viewport pairs with `scripts/ui/compare-screens.cjs`. Difference images and measurements include intentional tabs/footer/chart changes as well as live timestamps and moving time windows. They are review aids, not a claim of pixel identity. The largest viewport difference was 7.57% on Analytics at 1440×900. Analytical family tabs add 53 pixels to affected existing layouts. Live-intake content also differs because the isolated process was restarted.

The new contributor table appears beside its compact period chart. The bandwidth timeline remains dominant, with a narrower distribution panel. Endpoint/conversation tables keep scrolling inside their own container. At 1366×768, primary controls and initial table rows remain visible; larger desktop sizes expose more rows. The About dialog fits within the smallest reviewed viewport.

Artifacts:

- Baseline: `/tmp/cfc-insights.abPUjO/screens/before`
- Final existing routes: `/tmp/cfc-insights.abPUjO/screens/release-after`
- Final new analyses: `/tmp/cfc-insights.abPUjO/screens/release-insights`
- About: `/tmp/cfc-insights.abPUjO/screens/about`
- [Pixel comparison results](/tmp/cfc-insights.abPUjO/screens/release-diff/comparison.json)
- [Traffic changes, dark, 1366×768](/tmp/cfc-insights.abPUjO/screens/release-insights/changes-dark-1366x768.png)
- [Bandwidth, light, 1440×900](/tmp/cfc-insights.abPUjO/screens/release-insights/bandwidth-light-1440x900.png)
- [About and license, dark, 1366×768](/tmp/cfc-insights.abPUjO/screens/about/about-dark-1366x768.png)

## Remaining limits

- ClickHouse predicates and serialization were tested through the existing HTTP contract test pattern; no live ClickHouse integration environment was used for this change.
- Endpoint/conversation/IP analysis retains the existing 31-day limit. Rankings are bounded Top-N results, not a paginated complete inventory.
- A value outside a full comparison ranking remains unknown. P95 is a complete-bucket operational statistic; absent telemetry can represent collection gaps.
- The current query API cannot represent exact port-zero predicates, so those conversation direction buttons are disabled. Address profiles remain available.
- RPM packaging was validated for x86_64; arm64 binaries and Debian packaging were built, but an arm64 RPM was not tested.
- Browser checks establish functionality with the isolated dataset, not a production-scale throughput benchmark. Source changes and artifacts remain local; no repository push or production deployment was performed.

Workflow and API details: [Analytical views](../docs/ANALYSIS-VIEWS.md), [API](../docs/API.md).
