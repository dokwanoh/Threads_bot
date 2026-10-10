---
name: threads-spreader
description: Run the existing Threads spreader for aitr.endradar through the shared deployed browser ledger. Use for authorized distribution runs that vet Korean AI and technology posts, target five newly verified native reposts, and optionally make separately authorized useful replies, likes, or follows. This skill does not grant social permissions, deploy staged role queues, or change schedules.
---

# Threads Spreader

Read [the shared protocol](references/shared-protocol.md) first and apply it identically to manual and scheduled runs. Read the latest task/automation scope; action kinds outside it remain unavailable. Use only the dot cloud browser, existing account history/login, and exclusive shared writer.

## Find worthwhile candidates

Aim for five NEW verified native reposts per approved run. Vet as many candidates as needed; do not replace the goal with five candidates inspected or five clicks. Candidate vetting is not capped at five, but stop safely on a task deadline, exhausted qualifying sources, rate/security block, or unknown state and report a shortfall. Do not force a quota with poor or repeated material.

Prioritize Korean AI/technology content. Open the original post and inspect its text, original media, and relevant comments. Verify material factual claims against primary sources when possible; skip unsupported or misleading claims. Exclude advertising, paid promotion, reciprocal-follow/engagement bait, spam, sensitive content, and irrelevant posts. Never react based only on a feed snippet or screenshot caption.

For each candidate, verify the exact post/account, relevance, originality, and prior ledger/current UI state. Already reposted, liked, replied-to, or followed targets cannot count as new actions. Treat likes, reposts, replies, and follows as separate action keys and separate permissions.

## Native repost UI

Read current cloud-browser API documentation before constructing controls. Preflight is observation only: never click repost, like, or follow controls just to inspect state.

Before consuming an intent, establish that the documented browser route can ground the exact native-repost control without a preflight click. For a cold menu with no observed option, proceed only if the same bounded invocation can open once, observe the current menu, and derive the unambiguous exact locator from that real observation. If this requires an extra mutation invocation or guessing a selector, stop before `begin-write` and report the unsupported route. A readiness wait cannot create an observed locator.

After a fresh exact-target `begin-write` permit, execute that one bounded authorized browser invocation. Open the observed target's repost menu once. Ground the exact native-repost choice from actual current UI as above, then wait for it to become visible through the documented locator readiness API, within at most 5,000 ms and any shorter remaining permission/slot deadline. Inspect its current target and menu state, then select the native repost choice once only if unambiguous. Never choose quote, media/markup variants, undo, delete, or an already-reposted state.

The cached API documentation reviewed on 2026-10-10 defined `PlaywrightLocator.waitFor(options)` with `state` in `attached|detached|visible|hidden` and `timeoutMs`; verify these methods in current tool-returned documentation before using them. This is a documented readiness route, not a live-tested repost handler. Do not invent an undocumented sleep/wait API or unobserved locator.

If menu loading persists, the locator is absent/ambiguous, the target changes, or the supported route needs another mutation invocation, stop without re-clicking the opener or selecting blindly. The committed intent is not a reusable permit: report the exact UI state and preserve it for parent review. Use unknown/STOP handling when outcome is uncertain; do not call an un-deployed UI-abort/retry helper.

After each native repost, inspect persisted current repost state for the exact post/account and verify in the ledger. Count only newly verified reposts toward five. Readback failure never authorizes another click.

## Other separately authorized interactions

When the current scope permits replies, write a short useful Korean 반말 response specific to the original content or question. Add information, a grounded observation, or a relevant answer. Avoid generic praise, copied comments, reciprocal engagement, and invented personal experience. Read the full relevant conversation and check that we have not already replied to the exact parent before claiming.

Like only genuinely relevant content when separately authorized. Follow only an independently worthwhile account that is currently unfollowed, when follow permission covers it; inspect the profile and recent original posts, then perform the exact-profile duplicate check and separate permit. Never follow to hit a count or retry a denied follow. Each action requires its own complete shared-protocol cycle.

Release and hand off the checkpoint to the parent. Report new verified reposts out of five, separate reply/like/follow counts, candidates skipped, actual KST start/end times, result links, and any reason the goal remained unmet. Do not report already-present actions as new.
