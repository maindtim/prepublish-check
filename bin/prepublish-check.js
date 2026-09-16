#!/usr/bin/env node
import { scanPackage } from '../src/scan-package.js';
import { checkListing } from '../src/check-listing.js';

function parseArgs(argv) {
    const args = { dir: '.', url: null, paid: false, forbidden: [], ignore: [], json: false };
    for (let i = 0; i < argv.length; i += 1) {
        const a = argv[i];
        if (a === '--url') args.url = argv[++i];
        else if (a === '--paid') args.paid = true;
        else if (a === '--forbidden') args.forbidden = (argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
        else if (a === '--ignore') args.ignore = (argv[++i] || '').split(',').map((s) => s.trim()).filter(Boolean);
        else if (a === '--json') args.json = true;
        else if (!a.startsWith('--')) args.dir = a;
    }
    return args;
}

const ICON = { high: 'HIGH  ', medium: 'MEDIUM', low: 'LOW   ' };

const args = parseArgs(process.argv.slice(2));
const pkg = await scanPackage(args.dir, { ignore: args.ignore });
let listing = null;
if (args.url) {
    try {
        listing = await checkListing(args.url, { expectPaid: args.paid, forbidden: args.forbidden });
    } catch (err) {
        listing = { url: args.url, findings: [{ id: 'fetch-failed', severity: 'high', message: `Could not fetch the public page: ${err.message}` }] };
    }
}

const all = [...pkg.findings, ...(listing?.findings ?? [])];

if (args.json) {
    console.log(JSON.stringify({ package: pkg, listing, total: all.length }, null, 2));
} else {
    console.log(`\nPre-publish check — ${pkg.fileCount} files scanned in ${args.dir}`);
    if (listing) console.log(`Public page: ${listing.url} (HTTP ${listing.status ?? '-'}${listing.priceFound ? `, price seen: ${listing.priceFound}` : ''})`);
    console.log('');
    if (all.length === 0) {
        console.log('No findings. Package and listing look publishable.');
    } else {
        for (const f of all) {
            const where = f.file ? ` ${f.file}${f.line ? `:${f.line}` : ''}` : '';
            console.log(`[${ICON[f.severity]}] ${f.id}${where}`);
            console.log(`          ${f.message}`);
            if (f.excerpt) console.log(`          > ${f.excerpt}`);
        }
        const high = all.filter((f) => f.severity === 'high').length;
        console.log(`\n${all.length} finding(s), ${high} high severity.`);
    }
}

// Set the code instead of calling process.exit(): an in-flight keep-alive socket from the
// listing fetch can crash Node on Windows if the loop is torn down mid-request.
process.exitCode = all.some((f) => f.severity === 'high') ? 1 : 0;
