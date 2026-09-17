# Portal redesign: initial assessment

## Existing architecture to preserve

The portal is dependency-free JavaScript and CSS embedded in the Go HTTP server. Server APIs already aggregate analytics, compare periods, page flows with cursors, investigate hosts, produce network matrices, export reports and persist saved searches. Existing authentication, RBAC, intake admission controls and storage administration remain useful. No framework migration or new runtime dependency is warranted.

## Findings before implementation

- CSS contains successive redesign overrides, conflicting chart/table spacing and hard-coded theme colors. Components appear to belong to different generations.
- Overview presents eight equal cards before several equally weighted ranking panels. Traffic volume, rates and storage are mixed together, obscuring network state.
- Navigation has twelve primary items, including administration, policy and two traffic relationship entry points. These need grouping rather than deleting working functionality.
- Flow Explorer expands every filter into a permanently visible form. Supported interface, CIDR, TCP flag and duration filters are missing. No active filter chips, column controls or row detail exist.
- The query backend combines predicates with AND. OR/NOT, arbitrary secondary groupings and arbitrary cursor sorting are not supported. The UI must not imply otherwise.
- Navigation and flow URL updates discard the selected range. Analytics builder state and saved-view time settings are not restored reliably.
- The matrix API already returns bounded source/destination subnet aggregates. The current matrix renders a table and the map draws noninteractive links.
- Comparison colors incorrectly imply that traffic decreases are good. A zero previous period is displayed as a misleading percentage.
- Async route failures are not caught because route promises are returned without awaiting. Requests can race navigation. The global LIVE badge and collector-online text are initially unconditional.
- IP detail has useful sent/received and peer data but is constrained to a modal; it lacks page-level navigation and first/last-seen context.
- Reports support real server-generated PDF, XLSX, CSV and JSON but the configuration omits supported filters.
- Tables sanitize rich content, and cursor pagination bounds browser work. Preserve both.

## Design direction

A graphite instrument surface, restrained sea-glass accent, blue comparison series, small square geometry, quiet borders and tabular telemetry. Six-part telemetry rails replace floating KPI cards. The dominant timeline establishes temporal context; ranked lists expose exact values. Flow Lens chips provide one reusable filter vocabulary. A sparse, bounded network matrix becomes the product's distinctive relationship view. Themes share component rules through tokens.

## Review protocol

Capture before and after at 2560×1440, 1920×1080, 1440×900 and 1366×768. Cover every route, dark and light themes, and IP detail. Use an isolated collector and its actual authenticated API. Any generated UDP traffic is test input to the real decode/storage pipeline, never a mock API or shipped widget. Record empty and unavailable states separately. Automated geometry, console, request and interaction checks complement manual screenshot inspection; pixel change alone is not a correctness assertion.
