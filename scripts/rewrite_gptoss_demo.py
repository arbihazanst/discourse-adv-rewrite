#!/usr/bin/env python3
"""Generate explicitly labelled demonstrations with GPT-OSS, not validated evasions."""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phishbench.data import (read_dataset, read_csv, hash_file, atomic_csv, atomic_json,
                            append_checkpoint, load_row_checkpoint)
from phishbench.decision_api import authenticated_endpoint, post_json


def select_detected(rows, baseline):
    indexed = {r['row_id']: r for r in rows}
    if len(indexed) != len(rows):
        raise ValueError('Duplicate source row IDs')
    selected, seen = [], set()
    for prediction in baseline:
        rid = prediction['row_id']
        if rid in seen or rid not in indexed:
            raise ValueError('Duplicate or unknown baseline row ID')
        seen.add(rid)
        row = indexed[rid]
        if (prediction['original_sha256'] != row['original_sha256']
                or hashlib.sha256(row['original_text'].encode('utf-8')).hexdigest() != row['original_sha256']
                or prediction['dataset_label'] != row['dataset_label']):
            raise ValueError('Baseline/source provenance mismatch')
        if row['dataset_label'] == '1' and prediction['baseline_status'] == 'ok' and prediction['baseline_prediction'] == '1':
            selected.append(row)
    return selected


def demo_text(response):
    choices = response.get('choices', [])
    if len(choices) != 1:
        raise ValueError('Expected one GPT-OSS completion')
    choice = choices[0]
    message = choice.get('message', {})
    content = message.get('content')
    if (choice.get('finish_reason') in ('length', 'content_filter', 'tool_calls')
            or message.get('refusal') or message.get('tool_calls')
            or not isinstance(content, str) or not content.strip()):
        raise ValueError('Missing, refused, truncated or tool-call completion')
    text = content.strip()
    if not text.startswith('TRAINING EXAMPLE:'):
        raise ValueError('Completion lacks the explicit training-example label')
    if re.search(r'(?i)(?:https?|hxxps?)\s*:|www(?:\.|\[\.\])|\b[\w.+-]+@[\w.-]+\.[a-z]{2,}|\b[a-z0-9-]+\.[a-z]{2,}(?:\b|/)', text):
        raise ValueError('Completion contains a URL/domain/contact address instead of a placeholder')
    return text


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', default='data/phishrewrite/label1.csv')
    p.add_argument('--baseline', default='outputs/phishrewrite_pplx_test/pplx_decider_baseline.csv')
    p.add_argument('--prompt-file', default='templates/gptoss_demo_rewrite_prompt.txt')
    p.add_argument('--base-url', default='https://llms.si-lab.org')
    p.add_argument('--model', default='openai/gpt-oss-120b')
    p.add_argument('--api-key-env', default='OPENWEBUI_API_KEY')
    p.add_argument('--output-dir', default='outputs/phishrewrite_gptoss_demo')
    p.add_argument('--limit', type=int, default=3, help='Maximum detected positives to rewrite; 0 = all available')
    p.add_argument('--timeout', type=int, default=300)
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args()
    if args.limit < 0:
        p.error('--limit must be nonnegative')
    prompt = Path(args.prompt_file).read_text(encoding='utf-8').strip()
    if not prompt:
        raise ValueError('Prompt file is empty')
    baseline = read_csv(args.baseline)
    rows = select_detected(read_dataset(args.input, label='1'), baseline)
    available = len(rows)
    if args.limit:
        rows = rows[:args.limit]
    if not rows:
        raise ValueError('No source label-1 emails have valid baseline PHISHING predictions')
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    signature = {
        'input_sha256': hash_file(args.input), 'baseline_sha256': hash_file(args.baseline),
        'prompt_sha256': hashlib.sha256(prompt.encode('utf-8')).hexdigest(),
        'base_url': args.base_url, 'model': args.model, 'temperature': 0.2,
        'max_tokens': 2048, 'row_ids': [r['row_id'] for r in rows],
        'purpose': 'explicit_phishing_awareness_demo', 'valid_for_evasion_asr': False,
    }
    if args.dry_run:
        atomic_json(out / 'dry_run.json', {**signature, 'available_detected_positives': available})
        print(f'Dry run: {len(rows)} of {available} available baseline-detected positives; model={args.model}; no API requests.')
        return 0
    url, headers = authenticated_endpoint(args.base_url.rstrip('/') + '/api/chat/completions',
                                          args.api_key_env, require_systemone=False)
    manifest, journal = out / 'run.json', out / 'rewrites.checkpoint.jsonl'
    if manifest.exists():
        if json.loads(manifest.read_text(encoding='utf-8')) != signature:
            raise ValueError('Data, prompt or model changed; use a new output directory')
    elif journal.exists():
        raise ValueError('Checkpoint has no manifest')
    else:
        atomic_json(manifest, signature)
    cached = load_row_checkpoint(journal, ('candidate_text', 'review_status'))
    if set(cached) - set(signature['row_ids']):
        raise ValueError('Checkpoint contains unexpected rows')
    results = []
    for index, row in enumerate(rows, 1):
        item = cached.get(row['row_id'])
        if item is None:
            payload = {
                'model': args.model, 'stream': False, 'temperature': 0.2, 'max_tokens': 2048,
                'tools': [], 'tool_ids': [],
                'messages': [{'role': 'system', 'content': prompt},
                             {'role': 'user', 'content': json.dumps({'original_email': row['original_text']}, ensure_ascii=False)}],
            }
            response = post_json(url, payload, headers, timeout=args.timeout)
            text = demo_text(response)
            item = {
                'row_id': row['row_id'], 'original_sha256': row['original_sha256'],
                'dataset_label': '1', 'baseline_prediction': '1', 'method': 'gptoss_demo',
                'candidate_text': text, 'candidate_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
                'generator_model': args.model, 'prompt_sha256': signature['prompt_sha256'],
                'review_status': 'unreviewed', 'final_prediction': '',
                'rewrite_label': '', 'valid_for_evasion_asr': '0',
                'purpose': 'explicit_phishing_awareness_demo',
            }
            append_checkpoint(journal, item)
        if (item['original_sha256'] != row['original_sha256']
                or hashlib.sha256(item['candidate_text'].encode('utf-8')).hexdigest() != item['candidate_sha256']):
            raise ValueError('Checkpoint text hash mismatch')
        results.append(item)
        atomic_csv(out / 'rewrites.csv', results, list(results[0]))
        print(f'{index}/{len(rows)} {row["row_id"]}: demonstration saved', flush=True)
    print('Saved', out / 'rewrites.csv')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, ValueError) as exc:
        print('Generation stopped: ' + str(exc), file=sys.stderr)
        sys.exit(1)
