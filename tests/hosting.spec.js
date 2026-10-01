const { test, expect } = require('@playwright/test');

test('Workers serves wiki pages, search, feed, canonical URLs, and a real 404', async ({ request }) => {
  const home = await request.get('/');
  expect(home.status()).toBe(200);
  expect(await home.text()).toContain('Skillz Wiki');

  const skill = await request.get('/skills/httpx/');
  expect(skill.status()).toBe(200);
  expect(await skill.text()).toContain('https://skillz.wiki/skills/httpx/');

  const redirect = await request.get('/skills/httpx', { maxRedirects: 0 });
  expect([301, 307, 308]).toContain(redirect.status());
  expect(redirect.headers().location).toBe('/skills/httpx/');

  const search = await request.get('/search/search_index.json');
  expect(search.status()).toBe(200);
  const index = await search.json();
  expect(index.docs.length).toBeGreaterThan(100);
  expect(index.docs.some((entry) => entry.location.startsWith('skills/httpx/'))).toBe(true);

  const feed = await request.get('/feed.xml');
  expect(feed.status()).toBe(200);
  expect(await feed.text()).toContain('https://skillz.wiki/');

  const missing = await request.get('/cloudflare-migration-missing-page/');
  expect(missing.status()).toBe(404);
  expect(await missing.text()).toContain('404');
});
