/**
 * Checks a published page the way a stranger sees it: no session, no cookies.
 * Every rule here comes from a listing that looked fine in the dashboard and was broken in public.
 */
export function analyzeListingHtml(html, { expectPaid = false, forbidden = [] } = {}) {
    const findings = [];
    const text = html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<[^>]+>/g, ' ');
    const flat = text.replace(/\s+/g, ' ');

    const buyIndicators = /(buy now|add to cart|install skill|purchase|comprar)/i.test(flat);
    const freeIndicators = /(name your own price|download now|free download|\bfree\b)/i.test(flat);
    const priceMatch = flat.match(/(?:US)?\$\s?\d+(?:[.,]\d{2})?/);

    if (expectPaid) {
        if (!priceMatch) {
            findings.push({ id: 'price-not-visible', severity: 'high', message: 'No price is visible on the public page, but this product is supposed to be paid.' });
        }
        if (!buyIndicators) {
            findings.push({ id: 'no-buy-action', severity: 'high', message: 'No buy or install action found. A page can be public and still not purchasable (disabled downloads, draft pricing).' });
        }
        if (!buyIndicators && freeIndicators) {
            findings.push({ id: 'published-as-free', severity: 'high', message: 'The page offers a free download instead of a purchase. This is the single most expensive publishing mistake: live, visible, and earning nothing.' });
        }
    }

    if (/(this page is|no longer available|not found|404)/i.test(flat.slice(0, 600))) {
        findings.push({ id: 'page-error', severity: 'high', message: 'The public page looks like an error or unavailable page.' });
    }

    if (/(downloads?\s+(are\s+)?disabled|purchases?\s+disabled)/i.test(flat)) {
        findings.push({ id: 'downloads-disabled', severity: 'high', message: 'Downloads or purchases are disabled for this listing.' });
    }

    for (const term of forbidden) {
        if (!term) continue;
        if (new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i').test(flat)) {
            findings.push({ id: 'private-data-exposed', severity: 'high', message: `The public page contains "${term}". Owner identity or private data should not appear in a product listing.` });
        }
    }

    // Real listings phrase this in many ways ("built by Rock, an AI agent", "AI-made", "written with AI"),
    // so match the family of phrasings instead of one canonical sentence.
    const aiDisclosure = /(ai[- ](generated|assisted|made|written|built)|generative ai|(made|written|built|created|maintained)\s+(with|by)[^.]{0,40}\bai\b|an?\s+ai\s+(agent|assistant)\b)/i.test(flat);
    if (!aiDisclosure) {
        findings.push({ id: 'no-ai-disclosure', severity: 'medium', message: 'No AI disclosure found. Several marketplaces require it and de-rank or remove listings without it.' });
    }

    const words = flat.trim().split(/\s+/).length;
    if (words < 120) {
        findings.push({ id: 'thin-description', severity: 'medium', message: `The public page has about ${words} words. Thin listings convert badly and look abandoned.` });
    }

    return { priceFound: priceMatch ? priceMatch[0] : null, buyIndicators, aiDisclosure, words, findings };
}

/** Fetches the page without credentials and analyzes it. */
export async function checkListing(url, options = {}) {
    const res = await fetch(url, { redirect: 'follow', headers: { 'user-agent': 'prepublish-check/1.0 (+public listing verification)' } });
    if (!res.ok) {
        return { url, status: res.status, findings: [{ id: 'page-unreachable', severity: 'high', message: `The public URL returned HTTP ${res.status}. Buyers would see the same.` }] };
    }
    const html = await res.text();
    const result = analyzeListingHtml(html, options);
    return { url, status: res.status, ...result };
}
