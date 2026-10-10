---
name: threads-publisher
description: Run the existing Threads publisher for aitr.endradar using the shared deployed browser ledger. Use for authorized publisher schedule runs or requests to turn one new nedamma.tistory.com article into an original-image Threads root and three short continuation replies. This skill does not install or deploy a browser bot, edit schedules, or grant permission to post.
---

# Threads Publisher

Read [the shared protocol](references/shared-protocol.md) first and follow it in manual and scheduled runs. Resolve current automation scope and deployed documents every time. Use the dot cloud browser, the existing login/history, and the exclusive shared writer.

## Prepare one new article bundle

1. Read https://nedamma.tistory.com and select one relevant article/topic not already published by this account. Verify the actual numeric article URL and inspect the full article. Check both shared history and current Threads posts for the article and materially repeated topics. Do not infer a new topic from a changed URL or title.
2. Draft one root and exactly three ordered self-replies, roughly 150 Korean characters each unless the current approved task gives a narrower rule. Use clear, useful Korean, grounded in the article; do not manufacture claims or personal experience.
3. Put the exact verified numeric article URL in the first self-reply and require its visible link-preview card. A plain URL without the preview does not satisfy the bundle.
4. Use the article's original infographic. Retrieve and retain its exact original bytes, source URL, and SHA-256; visually verify the selected image matches the article and the intended upload. Do not replace it with a generated lookalike, unrelated thumbnail, or guessed image.
5. Freeze the complete four-part plan and image identity before dispatch. Establish the intended and ultimately observed parentage for each continuation. Do not reuse a parent key or change wording to bypass the ledger's shared reply/self_reply deduplication.

## Publish and verify

Choose the currently supported, authorized UI route without claiming it has already been live-tested:
- Single-composer bundle: when the approved scope allows root plus three Add-to-thread parts submitted once, bind all four exact texts, the article URL, attachment identity, and intended structure into one immutable `publish` payload. Use one claim, fresh preflight, and one-use permit for the one final bundle submission. Verify and bind all four distinct owned receipt URLs and the full image/preview/parentage evidence to that intent. The deployed v2 receipt list permits multiple owned receipts; it does not itself prove that the UI submitted a correct bundle.
- Separate submissions: give the root and each of the three self-replies their own claim, fresh absence check, one-use permit, submission, and persisted readback. The root uses `publish` with the numeric article URL as target; each continuation uses `self_reply` with its exact actual parent permalink. Use an ordered chain where necessary to respect the parent-key deduplication. One root permit cannot cover three later submit calls.

For either route, confirm actual browser support and final payload before dispatch. Do not infer support from staging code or an unfinished composer. Stop if the required UI preparation cannot fit the currently deployed safe control contract.

Before submitting, verify the original infographic is visibly attached to the root and the first continuation has the correct link preview. If preparation needs mutations the current one-call protocol cannot cover, stop and ask the parent to resolve that UI route before posting.

After submission, reload and verify all four parts: exact account, four distinct owned receipt URLs, correct order and parentage, final text, exact original infographic visibly present, and first self-reply's numeric URL plus preview card. Keep actual observation and image evidence. Do not call one visible root a completed bundle.

If a preview or image is missing before submit, do not submit that part. If missing after submit, retain the actual receipt, report the incomplete bundle, and stop further writes; do not delete, edit, or repost without new applicable approval and a supported reconciliation path. Ambiguous submissions follow the shared unknown/STOP path. Do not restart a partially published bundle from the root.

Release and request the parent's verified checkpoint acknowledgement as in the shared protocol. Report article link, root plus three reply links, verified parts out of four, image/preview checks, actual KST times, and any partial result or blocker. Report one new article bundle only after every part has passed readback; report durable completion only after acknowledgement.
