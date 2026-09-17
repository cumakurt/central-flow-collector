# UI / UX

The v4 information architecture is deliberately compact: Overview, Executive, Analytics, Flow Explorer, Traffic, Exporters, Reports and System. Desktop 1920×1080 and 2560×1440 are the primary layouts; notebook widths remain usable.

A common time range drives analytics pages. Visual Top-N elements drill into Flow Explorer. Flow Explorer keeps filter state in the URL and uses server-side cursor pagination. Saved Views persist filter/column/sort/group/visualization/time choices. Empty, loading and error states are explicit; the browser never attempts to load an unbounded raw dataset.
