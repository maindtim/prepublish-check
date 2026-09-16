import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const TEXT_EXT = new Set(['.md', '.txt', '.json', '.js', '.mjs', '.ts', '.py', '.sh', '.ps1', '.yml', '.yaml', '.toml', '.gd', '.html', '.css']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.godot', '__pycache__']);

/** Checks that come from real publishing failures. Each one carries the case that produced it. */
export const RULES = [
    {
        id: 'dangerous-command',
        severity: 'high',
        // Matches remote-installer one-liners and destructive/eval patterns, even inside prose.
        pattern: /(curl|wget)[^\n]{0,80}\|\s*(ba)?sh|rm\s+-rf\s+[^\n]|eval\s*\(|child_process|subprocess\.\w+\([^)]*shell\s*=\s*True/i, // prepublish-check-ignore
        message: 'Dangerous shell pattern in a shipped file. Marketplace scanners match strings, not intent: even a warning that quotes the command gets rejected. Describe it in words instead.',
    },
    {
        id: 'email-address',
        severity: 'high',
        pattern: /[\w.+-]+@(?!example\.|test\.)[\w-]+\.[a-z]{2,}/i, // prepublish-check-ignore
        message: 'Email address in a shipped file. Owner contact details do not belong in a public package.',
    },
    {
        id: 'absolute-path',
        severity: 'medium',
        pattern: /(?:[A-Z]:\\Users\\[^\\\s"']+|\/(?:home|Users)\/[^\/\s"']+)/, // prepublish-check-ignore
        message: 'Absolute path with a username. It leaks the machine owner and breaks on every other computer.',
    },
    {
        id: 'secret-like-token',
        severity: 'high',
        pattern: /\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|apify_api_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b/, // prepublish-check-ignore
        message: 'Looks like a live credential. Rotate it and move it out of the package.',
    },
    {
        id: 'phone-number',
        severity: 'medium',
        pattern: /(?:^|[\s(])\+\d{1,3}[\s-]?\d{6,}/,
        message: 'Phone number in a shipped file.',
    },
    {
        id: 'placeholder-left',
        severity: 'medium',
        pattern: /\b(TODO|FIXME|XXX|LOREM IPSUM|REPLACE ME|YOUR_API_KEY)\b/, // prepublish-check-ignore
        message: 'Unfinished placeholder. Buyers read this as abandoned work.',
    },
];

async function* walk(dir, root = dir) {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
        if (entry.name.startsWith('.') && entry.name !== '.gitignore') continue;
        if (SKIP_DIRS.has(entry.name)) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) yield* walk(full, root);
        else yield { full, rel: path.relative(root, full) };
    }
}

function parseFrontmatter(text) {
    const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
    if (!match) return null;
    const out = {};
    for (const line of match[1].split(/\r?\n/)) {
        const kv = /^([A-Za-z_-]+):\s*(.*)$/.exec(line);
        if (kv) out[kv[1]] = kv[2].trim();
    }
    return out;
}

/**
 * Scans a folder that is about to be published.
 * Returns findings sorted by severity, plus the file/line that produced each one.
 */
export async function scanPackage(dir, { maxFileMb = 5, ignore = [] } = {}) {
    const ignored = (rel) => ignore.some((p) => {
        const norm = rel.split(path.sep).join('/');
        const pat = p.split(path.sep).join('/').replace(/^\.\//, '');
        return norm === pat || norm.startsWith(pat.endsWith('/') ? pat : `${pat}/`) || norm.includes(pat);
    });
    const findings = [];
    let hasSkill = false;
    let hasLicense = false;
    let fileCount = 0;

    for await (const file of walk(dir)) {
        if (ignored(file.rel)) continue;
        fileCount += 1;
        const base = path.basename(file.rel).toLowerCase();
        if (base === 'skill.md') hasSkill = true;
        if (base === 'license' || base.startsWith('license.')) hasLicense = true;

        const info = await stat(file.full);
        if (info.size > maxFileMb * 1024 * 1024) {
            findings.push({ id: 'large-file', severity: 'medium', file: file.rel, line: 0, message: `File is ${(info.size / 1048576).toFixed(1)} MB. Marketplaces often reject or truncate large uploads.` });
        }
        if (!TEXT_EXT.has(path.extname(file.rel).toLowerCase())) continue;

        const text = await readFile(file.full, 'utf8');
        const lines = text.split(/\r?\n/);
        for (const rule of RULES) {
            lines.forEach((line, idx) => {
                // A line can opt out when the match is the rule itself or a deliberate example.
                if (line.includes('prepublish-check-ignore')) return;
                if (rule.pattern.test(line)) {
                    findings.push({ id: rule.id, severity: rule.severity, file: file.rel, line: idx + 1, message: rule.message, excerpt: line.trim().slice(0, 120) });
                }
            });
        }

        if (base === 'skill.md') {
            const fm = parseFrontmatter(text);
            if (!fm) {
                findings.push({ id: 'skill-frontmatter-missing', severity: 'high', file: file.rel, line: 1, message: 'SKILL.md has no YAML frontmatter. Registries need at least name and description.' });
            } else {
                if (!fm.name) findings.push({ id: 'skill-name-missing', severity: 'high', file: file.rel, line: 1, message: 'Frontmatter is missing "name".' });
                if (!fm.description) findings.push({ id: 'skill-description-missing', severity: 'high', file: file.rel, line: 1, message: 'Frontmatter is missing "description": it is what makes the skill trigger.' });
                else if (fm.description.length < 60) findings.push({ id: 'skill-description-short', severity: 'low', file: file.rel, line: 1, message: 'Description is very short. Name the situations that should trigger the skill.' });
            }
        }
    }

    if (!hasSkill) findings.push({ id: 'no-skill-md', severity: 'low', file: '.', line: 0, message: 'No SKILL.md found. Skill marketplaces require one at the package root.' });
    if (!hasLicense) findings.push({ id: 'no-license', severity: 'medium', file: '.', line: 0, message: 'No LICENSE file. Buyers and reviewers check usage rights before installing.' });
    if (fileCount === 0) findings.push({ id: 'empty-package', severity: 'high', file: '.', line: 0, message: 'The folder is empty.' });

    const order = { high: 0, medium: 1, low: 2 };
    findings.sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file));
    return { fileCount, findings };
}
