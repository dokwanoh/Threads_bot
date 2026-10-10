"""Fail-closed staging publisher bundle checks; no browser or production handler.

This checks exact payload/evidence binding and persisted observations. It cannot
attest native tool provenance or visually judge an infographic. Those remain the
assigned native worker's job. A numeric article URL or one receipt alone is never
sufficient. UI preparation is not implemented or disguised as read-only preflight.
"""
from pathlib import Path
import base64
import binascii
import hashlib
import time
from urllib.parse import urlsplit

from dispatch_gate import (DispatchGate, GateBlocked, HASH, action_id, canonical,
                           parse_json, payload_hash, require, successful)

from integration_paths import INTEGRATION_ROOT as STAGING_ROOT
PAYLOAD_KEYS = {'target', 'article_id', 'blog_url', 'root', 'replies',
                'root_image_path', 'root_image_url', 'image_sha256', 'preview_reply_index'}
PROOF_KEYS = {'schema', 'account', 'target', 'payload_hash', 'intent_id', 'observed_at',
              'parts', 'image', 'preview', 'reloaded', 'reload_reference', 'source_records', 'original_image'}
MAX_PROOF_BYTES = 8_000_000
MAX_CONTENT_BYTES = 5_500_000
MAX_ORIGINAL_IMAGE_BYTES = 4_000_000  # Reserve bounded space for native observations.


def _file(path):
    require(type(path) is str and Path(path).is_absolute() and
            Path(path).resolve().is_relative_to(STAGING_ROOT), 'Publisher evidence must remain in staging')
    require(all(not p.is_symlink() for p in (Path(path), *Path(path).parents)), 'Publisher symlink path prohibited')
    return DispatchGate._bounded_file(path)


def _text(value):
    require(type(value) is str and 0 < len(value) <= 4000 and bool(value.strip()), 'Exact nonempty part text required')


def validate_payload(action, *, retained_image=None):
    if action.get('kind') != 'publish':
        return
    payload = action.get('payload')
    require(type(payload) is dict and set(payload) == PAYLOAD_KEYS, 'Complete immutable publish bundle required')
    target = action.get('target')
    # Reuse the exact ledger URL semantics; this checks shape, not observation.
    action_id('synthetic_validation', 'publish', target)
    article = int(urlsplit(target).path.rstrip('/').split('/')[-1])
    require(payload['target'] == target and payload['blog_url'] == target and
            type(payload['article_id']) is int and payload['article_id'] == article,
            'Publisher article identity differs from exact target')
    _text(payload['root'])
    require(type(payload['replies']) is list and len(payload['replies']) == 3, 'Exactly three ordered continuation parts required')
    for text in payload['replies']: _text(text)
    require(type(payload['preview_reply_index']) is int and payload['preview_reply_index'] == 1 and
            target in payload['replies'][0], 'First continuation must include exact article URL and preview')
    _text(payload['root_image_url'])
    source = urlsplit(payload['root_image_url'])
    require(source.scheme == 'https' and bool(source.hostname) and source.username is None and
            source.password is None and not source.fragment, 'Exact HTTPS original image source required')
    require(type(payload['image_sha256']) is str and HASH.fullmatch(payload['image_sha256']), 'Original image digest required')
    # Retained verification uses the exact archived bytes, never an old runtime path.
    data = _file(payload['root_image_path']) if retained_image is None else retained_image
    require(len(data) <= MAX_ORIGINAL_IMAGE_BYTES, 'Original image exceeds the retained-proof preparation limit')
    require(bool(data) and hashlib.sha256(data).hexdigest() == payload['image_sha256'], 'Original image file differs from pinned bytes')
    require(data.startswith((b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff', b'GIF87a', b'GIF89a')) or
            (data.startswith(b'RIFF') and data[8:12] == b'WEBP'), 'Recognized original raster image bytes required')
    if 'payload_hash' in action:
        require(action['payload_hash'] == payload_hash(payload), 'Publisher payload digest changed')


def _owned_receipt(url, account):
    action_id(account, 'reply', url)
    parsed = urlsplit(url)
    require(parsed.path.split('/')[1].lower() == '@' + account, 'Receipt belongs to a different account')


def _embedded(value):
    require(type(value) is dict and set(value) == {'sha256', 'size', 'base64'}, 'Exact embedded source required')
    require(type(value['sha256']) is str and HASH.fullmatch(value['sha256']) and
            type(value['size']) is int and 0 < value['size'] <= MAX_CONTENT_BYTES and
            type(value['base64']) is str and len(value['base64']) <= 4*((MAX_CONTENT_BYTES+2)//3),
            'Embedded source size or digest invalid')
    try:
        data = base64.b64decode(value['base64'], validate=True)
    except (binascii.Error, ValueError):
        raise GateBlocked('Embedded source encoding invalid') from None
    require(base64.b64encode(data).decode() == value['base64'] and len(data) == value['size'] and
            hashlib.sha256(data).hexdigest() == value['sha256'], 'Embedded source bytes mismatch')
    return data


def _embed(data):
    require(type(data) is bytes and 0 < len(data) <= MAX_CONTENT_BYTES, 'Bounded source bytes required')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data),
            'base64': base64.b64encode(data).decode()}


def make_self_contained_proof(proof, action):
    """Convert actual persisted native observations to a retained v2 proof.

    This is local packaging, not native provenance or visual attestation. The
    original v1 dictionary is not edited, and no ledger or service is contacted.
    """
    validate_payload(action)
    require(type(proof) is dict and set(proof) == PROOF_KEYS - {'original_image'} and
            proof['schema'] == 'publisher-bundle-readback-v1', 'Exact unsealed bundle source required')
    result = parse_json(canonical(proof))
    records = result['source_records']
    require(type(records) is list and 1 <= len(records) <= 16, 'Bounded native source records required')
    total = 0
    for record in records:
        require(type(record) is dict and set(record) == {'reference', 'path', 'sha256'}, 'Exact native source record required')
        data = _file(record['path'])
        require(hashlib.sha256(data).hexdigest() == record['sha256'], 'Native source changed before retention')
        total += len(data)
        record['embedded'] = _embed(data)
    image = _file(action['payload']['root_image_path'])
    total += len(image)
    require(total <= MAX_CONTENT_BYTES, 'Combined native evidence exceeds bounded proof size')
    result['original_image'] = _embed(image)
    result['schema'] = 'publisher-bundle-readback-v2'
    require(len(canonical(result).encode()) <= MAX_PROOF_BYTES, 'Retained proof exceeds ledger evidence limit')
    return result


def validate_present_bundle(value, action, binding, intent_id, *, now):
    validate_payload(action)
    require(binding['role'] == 'publisher', 'Publish bundle is assigned to the publisher role only')
    evidence = value.get('evidence')
    require(type(evidence) is dict and evidence.get('outcome') == 'present', 'Complete present bundle evidence required')
    receipts = evidence.get('receipt_urls')
    require(type(receipts) is list and len(receipts) == 4 and
            all(type(url) is str for url in receipts) and len(set(receipts)) == 4,
            'All four exact observed receipt URLs are required')
    for receipt in receipts: _owned_receipt(receipt, binding['account'])
    require(len({action_id(binding['account'], 'reply', url) for url in receipts}) == 4,
            'All four receipts must identify distinct canonical posts')
    raw = _file(evidence['proof_file'])
    require(hashlib.sha256(raw).hexdigest() == evidence['proof_sha256'], 'Bundle proof file digest mismatch')
    proof = parse_json(raw.decode())
    return validate_retained_bundle(proof, action, binding, intent_id, receipts=receipts, now=now,
                                    compare_live_sources=True)


def validate_retained_bundle(proof, action, binding, intent_id, *, receipts, now,
                             compare_live_sources=False):
    """Validate self-contained checkpoint proof without relying on old file paths.

    `now` is the trusted observation validation time for historical restore, not
    permission to perform any new action. This function is read-only.
    """
    require(type(proof) is dict and set(proof) == PROOF_KEYS and
            proof['schema'] == 'publisher-bundle-readback-v2', 'Self-contained native bundle proof required')
    require(len(canonical(proof).encode()) <= MAX_PROOF_BYTES, 'Retained proof is oversized')
    image_bytes = _embedded(proof['original_image'])
    validate_payload(action, retained_image=image_bytes)
    require(binding['role'] == 'publisher', 'Publisher binding required')
    require(type(receipts) is list and len(receipts) == 4 and all(type(url) is str for url in receipts) and
            len(set(receipts)) == 4,
            'Four distinct retained receipts required')
    for receipt in receipts: _owned_receipt(receipt, binding['account'])
    require(len({action_id(binding['account'], 'reply', url) for url in receipts}) == 4,
            'Four distinct canonical retained posts required')
    expected = {'account': binding['account'], 'target': action['target'],
                'payload_hash': action['payload_hash'], 'intent_id': intent_id}
    require(all(type(proof[k]) is type(v) and proof[k] == v for k, v in expected.items()),
            'Publisher proof identity, payload or intent mismatch')
    require(type(now) is int and type(proof['observed_at']) is int and
            now - 300 <= proof['observed_at'] <= now, 'Publisher readback is stale or future-dated')
    records = proof['source_records']
    require(type(records) is list and 1 <= len(records) <= 16, 'Actual persisted native observations required')
    sources = {}
    total = len(image_bytes)
    for record in records:
        require(type(record) is dict and set(record) == {'reference', 'path', 'sha256', 'embedded'}, 'Exact retained observation record required')
        _text(record['reference'])
        require(record['reference'] not in sources and type(record['sha256']) is str and
                HASH.fullmatch(record['sha256']), 'Unique observation reference/hash required')
        data = _embedded(record['embedded'])
        total += len(data)
        require(total <= MAX_CONTENT_BYTES, 'Combined retained evidence is oversized')
        if compare_live_sources:
            require(data == _file(record['path']), 'Retained source differs from actual native file')
        require(bool(data) and hashlib.sha256(data).hexdigest() == record['sha256'], 'Observation bytes differ from native record')
        sources[record['reference']] = data
    def source(reference):
        require(type(reference) is str and reference in sources, 'Observation reference has no persisted source')
        return sources[reference]
    parts = proof['parts']
    texts = [action['payload']['root'], *action['payload']['replies']]
    require(type(parts) is list and len(parts) == 4, 'Exact ordered four-part readback required')
    for index, part in enumerate(parts):
        require(type(part) is dict and set(part) == {'url', 'parent_url', 'account', 'text', 'observation_reference'},
                'Exact per-part account/text/connection evidence required')
        require(part['url'] == receipts[index] and part['account'] == binding['account'] and
                part['text'] == texts[index] and part['parent_url'] == (None if index == 0 else receipts[index-1]),
                'Part text/order/owner/parent does not match prepared bundle')
        body = source(part['observation_reference'])
        require(part['url'].encode() in body and
                (part['text'].encode() in body or canonical(part['text']).encode() in body),
                'Actual observation does not contain the part URL/text')
    image = proof['image']
    require(type(image) is dict and set(image) == {'part_url', 'source_sha256', 'visible', 'visual_match', 'observation_reference'} and
            image['part_url'] == receipts[0] and image['source_sha256'] == action['payload']['image_sha256'] and
            image['visible'] is True and image['visual_match'] is True, 'Root original-image readback is incomplete')
    source(image['observation_reference'])  # Native visual judgment still required; not authenticated by JSON.
    preview = proof['preview']
    require(type(preview) is dict and set(preview) == {'part_url', 'href', 'card_text', 'observation_reference'} and
            preview['part_url'] == receipts[1] and preview['href'] == action['target'], 'First-part preview/destination mismatch')
    _text(preview['card_text'])
    body = source(preview['observation_reference'])
    require(preview['href'].encode() in body and preview['card_text'].encode() in body, 'Preview source lacks actual card/destination')
    require(proof['reloaded'] is True, 'Actual reload observation is required')
    source(proof['reload_reference'])
    return proof


class PublisherAuthorizationGuard:
    def __init__(self, delegate): self.delegate = delegate
    def authorize_batch(self, job, actions):
        for action in actions:
            if action['kind'] == 'publish':
                require(job['role'] == 'publisher', 'Wrong role for publish')
                validate_payload(action)
        return self.delegate.authorize_batch(job, actions)
    def authorize(self, job, action):
        validate_payload(action)
        return self.delegate.authorize(job, action)


class PublisherBrowserGuard:
    def __init__(self, delegate, *, clock=None):
        self.delegate = delegate
        self.clock = clock or (lambda: int(time.time()))
    def observe(self, binding): return self.delegate.observe(binding)
    def preflight(self, action, binding):
        validate_payload(action)
        result = self.delegate.preflight(action, binding)
        if action['kind'] == 'publish':
            value = successful(result)
            if value.get('evidence', {}).get('outcome') == 'present':
                validate_present_bundle(value, action, binding, None, now=self.clock())
        return result
    def mutate(self, action, binding, intent_id, *, slot_start, slot_deadline):
        validate_payload(action)
        return self.delegate.mutate(action, binding, intent_id, slot_start=slot_start, slot_deadline=slot_deadline)
    def readback(self, action, binding, intent_id):
        result = self.delegate.readback(action, binding, intent_id)
        if action['kind'] == 'publish':
            validate_present_bundle(successful(result), action, binding, intent_id, now=self.clock())
        return result


def guarded_coordinator(queue, identity, *, clock, ledger, browser, authorization, **kwargs):
    """Explicit safe integration entry point. Still enables no actual transport."""
    from coordinator import SerialCoordinator
    return SerialCoordinator(queue, identity, clock=clock, ledger=ledger,
        browser=PublisherBrowserGuard(browser, clock=clock),
        authorization=PublisherAuthorizationGuard(authorization), **kwargs)
