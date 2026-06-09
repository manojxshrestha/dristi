// Playwright MCP init script — runs in every page before page scripts
// Patches automation fingerprints that Cloudflare/WAFs detect.
// Pass via: --init-script scripts/playwright-stealth.js

// Patch webdriver flag — #1 detection method
Object.defineProperty(navigator, 'webdriver', { get: () => false });

// Patch plugins array — headless has empty array
Object.defineProperty(navigator, 'plugins', {
  get: () => [
    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
    { name: 'Native Client', filename: 'internal-nacl-plugin' },
  ],
});

// Patch languages — headless often returns only ['en-US']
Object.defineProperty(navigator, 'languages', {
  get: () => ['en-US', 'en', 'es', 'fr'],
});

// Override permissions query to mask headless behavior
const originalQuery = navigator.permissions.query.bind(navigator.permissions);
navigator.permissions.query = (desc) => {
  if (desc.name === 'notifications') {
    return Promise.resolve({ state: 'prompt', onchange: null });
  }
  return originalQuery(desc);
};

// Add chrome.runtime — real Chrome has it
if (!window.chrome) {
  window.chrome = { runtime: { id: 'chrome-extension' } };
}
