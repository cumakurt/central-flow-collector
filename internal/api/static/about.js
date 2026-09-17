'use strict';

async function showAbout() {
  try {
    const info = await cachedAPI('/api/v1/about'), p = info.product;
    openModal(`<section class="product-about"><div class="modal-heading"><span class="eyebrow">ABOUT / CENTRAL FLOW COLLECTOR</span><h3>${esc(p.name)}</h3><p class="muted">Network telemetry, flow analytics and operational visibility.</p></div><dl class="about-details"><div><dt>Developer</dt><dd>${esc(p.developer)}</dd></div><div><dt>Contact</dt><dd><a href="mailto:${esc(p.email)}">${esc(p.email)}</a></dd></div><div><dt>LinkedIn</dt><dd><a href="${esc(p.linkedin)}" target="_blank" rel="noopener noreferrer">Cuma KURT on LinkedIn ↗</a></dd></div><div><dt>Source code</dt><dd><a href="${esc(p.source)}" target="_blank" rel="noopener noreferrer">github.com/cumakurt/central-flow-collector ↗</a></dd></div><div><dt>License</dt><dd><a href="${esc(p.license_url)}" target="_blank" rel="noopener">${esc(p.license)} · Read the full license ↗</a><small>GNU Affero General Public License, version 3 only.</small></dd></div><div><dt>Build</dt><dd><code>${esc(info.version)}</code>${info.commit !== 'unknown' ? ` · <code>${esc(info.commit)}</code>` : ''}${info.build_time !== 'unknown' ? `<small>${esc(info.build_time)}</small>` : ''}</dd></div></dl><footer class="about-notice"><p>${esc(p.copyright)}</p><p>This program comes with no warranty. You may redistribute and modify it under AGPL-3.0-only; see the license for its terms.</p></footer></section>`);
    $('modalBody').querySelector('a')?.focus();
  } catch (error) {
    toast('Unable to load project information. Retry when the collector is reachable.','bad');
  }
}
