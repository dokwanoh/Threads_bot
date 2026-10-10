# Native Repost selector guidance

This is a source-only correction for future separately authorized work. It does
not run a browser, deploy a selector, resolve an unknown result, clear STOP, or
permit retrying a consumed intent. Existing writer, authorization, quarantine,
freshness, duplicate and checkpoint gates still apply.

## Exact role and complete observed name

Ground the native choice in an authentic read-only accessibility snapshot and the
current supported browser API. The opener is a button; the final native choice
is a menu item. Text plus a named icon can produce a repeated accessible label.
For example, this **synthetic** snapshot uses a complete doubled name:

```text
- menu:
  - menuitem "리포스트 리포스트":
    - generic: 리포스트
    - img "리포스트"
  - menuitem "인용하기 인용하기":
```

The doubled label is not a universal constant. Do not hardcode it from this
example without actual grounding. Where the current tool documents these APIs,
use the exact complete observed name, preferably within the observed menu:

```javascript
tab.playwright.getByRole('menu').getByRole('menuitem', {
  name: observedNativeAccessibleName, exact: true
})
```

Page-wide `getByText` can match hidden SVG title elements as well as a visible
label. One visible match does not make three total matches unambiguous. Never
fall back to global text, a guessed shorter name, `first`, `nth`, quote selection,
or a different action type. The historical request template in
`quarantine_extension.py` recognizes one failed request for evidence validation;
it is not a recommended browser invocation or a new dispatch implementation.

## One bounded invocation after all existing gates

1. Check fresh exact-target permission, URL, actual account, not-already-reposted
   state, and a unique grounded opener. The native item's full name must already
   be grounded in authentic UI evidence rather than guessed after a failure.
2. Open the menu once, construct that exact role/name locator, and perform the
   documented `waitFor({state: 'visible', timeoutMs: ...})` once. Bound the wait by
   5,000 ms and the shorter remaining permission/slot window. Do not demand a
   fully loaded snapshot, item count or item visibility immediately after opening
   before this readiness wait. No remaining time, timeout or error means stop.
3. After readiness, obtain a fresh snapshot and require one relevant menu and
   one exact native candidate. Recheck current role, complete name and meaning,
   URL/account, permission and not-already-reposted state. Independently reject
   undo/delete/cancel-repost or other reversal states, even if a native-looking
   exact name is also present. Never choose quote or a media/markup variant.
4. Check the same locator has count one and is visible and enabled. Recheck the
   remaining authorization time immediately before its one final click; bound
   click timeout by that window. No reopening, replacement locator or retry is
   allowed after failure or uncertainty. Real persisted readback and the ledger's
   verification are still required before counting a newly completed repost.

This procedure is not an executed browser test. Supported APIs, menu-scoped
behavior, current names and genuine observations require the authorized native
worker's current checks. A locator failure during a mutation is not an eligible
read-only failure for the three-error diagnostic rule.

## Regression scope

`test_repost_selector_contract.py` uses inline synthetic text snapshots and
selector-count fixtures only. It checks a small exact-name model, including
quote/short-name/duplicate rejection and hidden-title ambiguity. Its explicit
reversal-state counterexample demonstrates that name selection alone does not
implement the separate semantic reversal guard. It is not a DOM parser, an
accessibility-name algorithm, a Playwright execution, a readiness/click test, or
proof of a complete safe runtime route. No browser transport is added.
