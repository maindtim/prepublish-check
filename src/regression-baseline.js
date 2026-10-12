import { RULES } from './scan-package.js';

/**
 * Checks one pinned regression case against the live rule set.
 *
 * A baseline entry pins `ruleId` + `ruleVersion` (the rule's own `version` tag at the time the
 * case was written) together with one `line` and the `expectHit` that line should produce.
 * Comparing `line` against the rule's current pattern only means something if the rule is the
 * same rule the entry was pinned against. Two ways it can stop being the same rule:
 *
 * - the `ruleId` no longer exists in `RULES` (the check was removed or renamed), or
 * - the rule exists but its `version` no longer equals `ruleVersion` (the entry was pinned against
 *   a different revision of the rule, in either direction).
 *
 * Either way, a straight pass/fail would be a guess dressed up as a result. This returns a
 * third state, `stale_baseline`, instead of defaulting to pass or to fail.
 */
export function checkBaseline(entry) {
    const rule = RULES.find((r) => r.id === entry.ruleId);
    if (!rule) {
        return { status: 'stale_baseline', reason: `rule "${entry.ruleId}" no longer exists` };
    }
    if (rule.version !== entry.ruleVersion) {
        return {
            status: 'stale_baseline',
            reason: `rule "${entry.ruleId}" is at version ${rule.version}, this entry was pinned to ${entry.ruleVersion}`,
        };
    }
    const hit = rule.pattern.test(entry.line);
    return { status: hit === entry.expectHit ? 'pass' : 'fail', hit };
}

/** Runs `checkBaseline` over a list of entries and totals the three states. */
export function checkBaselineSet(entries) {
    const results = entries.map((entry) => ({ entry, ...checkBaseline(entry) }));
    const counts = { pass: 0, fail: 0, stale_baseline: 0 };
    for (const r of results) counts[r.status] += 1;
    return { results, counts };
}
