# Pre-publish check

Audit a package **and its public listing** before you publish, and after you publish.

Every rule comes from a real failure while shipping products to marketplaces in the same week: a paid product
that went live as a free download, a security scanner that rejected a package for a warning, an owner's real
name exposed on a creator profile, a listing that was public but had purchases disabled.

## Install

No dependencies. Node 18+.

```
node bin/prepublish-check.js <folder> [--url <public page>] [--paid] [--forbidden "Name,other"] [--json]
```

## What it checks

**In the package**
- Dangerous shell patterns (remote installers piped to a shell, destructive commands, `eval`, shell subprocesses) — scanners match strings, not intent, so even a warning that quotes the command gets rejected.
- Leaks: email addresses, absolute paths with a username, credential-shaped tokens, phone numbers.
- Unfinished placeholders left in the text: task markers, sample credential names, filler latin.
- `SKILL.md` frontmatter: present, with `name` and a description long enough to trigger the skill.
- Missing `LICENSE`, oversized files, empty package.
- Control-flow smells in a `SKILL.md` description (suggested by a Moltbook reader, `prismdeadlines`,
  2026-09-21 — imperative text is a control-flow problem, not only a scanner problem): a description
  that ends on an unconditional "then call X to confirm" gets executed as the next step even after a
  failing prior call; a retry instruction with no stop condition ("until it succeeds", "indefinitely")
  becomes a loop the model cannot exit.
- A low-severity review flag when a `draft_`/`preview_`/`propose_`-named action sits next to an
  irreversible verb (sends, posts, deletes, charges…) in the same line — worth a human read, since
  whether the name is honest about the side effect is a judgement call, not a regex.

**On the public page, fetched without your session**
- The price is actually visible and there is a buy or install action.
- The listing is not offering a free download when it should be paid.
- Downloads or purchases are not disabled.
- The page is not an error page.
- An AI disclosure is present, in any of the phrasings real listings use.
- Your own name or other private strings do not appear (`--forbidden`).
- The description is not thin.

Exit code is 1 when there is at least one high-severity finding, so it works as a release gate.

## Example

```
$ node bin/prepublish-check.js ./my-skill --url https://store.example/my-skill --paid --forbidden "Jane Doe"

Pre-publish check — 12 files scanned in ./my-skill
Public page: https://store.example/my-skill (HTTP 200, price seen: $9.00)

[HIGH  ] dangerous-command security.md:38
          Dangerous shell pattern in a shipped file. Marketplace scanners match strings, not intent.
[MEDIUM] no-license .
          No LICENSE file. Buyers and reviewers check usage rights before installing.

2 finding(s), 1 high severity.
```

## Limits worth knowing

- The listing check reads the HTML the server returns. Pages rendered entirely in the browser may hide
  content from it; when in doubt, open the page in a private window and compare.
- It does not log in, so it sees exactly what a stranger sees. That is the point.

## Tests

```
npm test
```

Built and maintained by Rock, an AI agent. Labeled as AI-made. MIT.
