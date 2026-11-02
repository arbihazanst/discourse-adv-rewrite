#!/usr/bin/env python3
"""Classify original PhishRewrite positives with the existing PPLX transports."""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phishbench.classification import INSTRUCTIONS, CRITERIA
from phishbench.data import (read_dataset, atomic_csv, atomic_json, append_checkpoint,
                            load_row_checkpoint, hash_file)
from phishbench.decision_api import authenticated_endpoint, post_json, choice_answer
from phishbench.openwebui_decider import request_decision
from scripts.baseline_metrics import metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', default='data/phishrewrite/label1.csv')
    parser.add_argument('--output-dir', default='outputs/phishrewrite_pplx_test')
    parser.add_argument('--transport', choices=['openwebui', 'direct'], default='openwebui')
    parser.add_argument('--webui-url', default='https://llms.si-lab.org')
    parser.add_argument('--chat-model', default='openai/gpt-oss-120b')
    parser.add_argument('--tool-id', default='server:pplxdeciderflash')
    parser.add_argument('--endpoint-url', default=os.getenv('PPLX_SYSTEMONE_URL'))
    parser.add_argument('--model', default=os.getenv('PPLX_MODEL_ID'))
    parser.add_argument('--api-key-env')
    parser.add_argument('--limit', type=int, default=10, help='First N label-1 emails for a smoke test; 0 = all')
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--request-attempts', type=int, default=3)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if args.limit < 0:
        parser.error('--limit must be nonnegative')
    if args.transport == 'direct' and (not args.endpoint_url or not args.model):
        parser.error('Direct transport needs --endpoint-url and --model (or PPLX_SYSTEMONE_URL/PPLX_MODEL_ID)')
    key_env = args.api_key_env or ('OPENWEBUI_API_KEY' if args.transport == 'openwebui' else 'PPLX_API_KEY')
    rows = read_dataset(args.input, label='1')
    if args.limit:
        rows = rows[:args.limit]
    if not rows:
        raise ValueError('No original label-1 emails selected')
    ids = set()
    for row in rows:
        if row['row_id'] in ids or not row['row_id']:
            raise ValueError('Missing or duplicate row ID')
        ids.add(row['row_id'])
        if hashlib.sha256(row['original_text'].encode('utf-8')).hexdigest() != row['original_sha256']:
            raise ValueError('Source text hash mismatch')
    destination = Path(args.output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    signature = {
        'dataset_sha256': hash_file(args.input), 'row_ids': [r['row_id'] for r in rows],
        'label_filter': '1', 'transport': args.transport, 'limit': args.limit,
        'classification_task_sha256': hashlib.sha256(json.dumps([INSTRUCTIONS, CRITERIA], sort_keys=True).encode()).hexdigest(),
        'connection': ({'webui_url': args.webui_url, 'chat_model': args.chat_model, 'tool_id': args.tool_id}
                       if args.transport == 'openwebui' else {'endpoint_url': args.endpoint_url, 'model': args.model}),
    }
    if args.dry_run:
        atomic_json(destination / 'dry_run.json', signature)
        print(f'Dry run: {len(rows)} label-1 originals; transport={args.transport}; no requests sent.')
        return 0
    # Validate credentials before committing any run state; never save the key.
    endpoint = (args.webui_url.rstrip('/') + '/api/chat/completions'
                if args.transport == 'openwebui' else args.endpoint_url)
    url, headers = authenticated_endpoint(endpoint, key_env, require_systemone=args.transport == 'direct')
    manifest = destination / 'pplx_decider_baseline.csv.run.json'
    journal = destination / 'pplx_decider_baseline.csv.checkpoint.jsonl'
    output = destination / 'pplx_decider_baseline.csv'
    if manifest.exists():
        if json.loads(manifest.read_text(encoding='utf-8')) != signature:
            raise ValueError('Run settings changed; select a different output directory')
    elif journal.exists() or output.exists():
        raise ValueError('Existing predictions have no manifest; select a different output directory')
    else:
        atomic_json(manifest, signature)
    cached = load_row_checkpoint(journal, ('baseline_status', 'baseline_prediction', 'dataset_label'))
    if set(cached) - ids:
        raise ValueError('Checkpoint contains rows outside this run')
    atomic_csv(destination / 'selected_input.csv', rows, list(rows[0]))
    results = []
    def save_response(response):
        # Public email/tool evidence only; redact any accidental credential echo.
        serialized = json.dumps(response)
        key = os.environ.get(key_env, '')
        if key:
            serialized = serialized.replace(json.dumps(key)[1:-1], '[REDACTED]')
        atomic_json(destination / 'last_response.json', json.loads(serialized))

    for index, row in enumerate(rows, 1):
        item = cached.get(row['row_id'])
        if item is not None:
            if (item['original_sha256'] != row['original_sha256'] or item['dataset_label'] != '1'
                    or item['baseline_status'] != 'ok' or item['baseline_prediction'] not in ('0', '1')):
                raise ValueError('Checkpoint does not match the source or a valid decision')
        else:
            payload = {'model': args.model, 'state': row['original_text'],
                       'questions': {'email_class': {'type': 'choice', 'instructions': INSTRUCTIONS, 'criteria': CRITERIA}}}
            try:
                if args.transport == 'openwebui':
                    response, evidence = request_decision(args.webui_url, args.chat_model, args.tool_id, payload,
                                                          key_env, args.timeout, args.request_attempts,
                                                          response_observer=save_response, escape_unicode=True)
                else:
                    response = post_json(url, payload, headers, args.timeout, args.request_attempts)
                    evidence = {'decision_tool_source': 'direct_systemone',
                                'decision_tool_result_sha256': hashlib.sha256(json.dumps(response, sort_keys=True).encode()).hexdigest()}
            except (RuntimeError, ValueError) as exc:
                # No email content, credentials, or unverified prediction enters the error log.
                atomic_json(destination / 'last_error.json', {
                    'row_id': row['row_id'], 'position': index, 'error_type': type(exc).__name__,
                    'diagnostics': getattr(exc, 'diagnostics', {}),
                    'completed_rows': len(results), 'prediction_recorded': False,
                })
                raise
            choice, probability, confidence = choice_answer(response, 'email_class', CRITERIA)
            # Validate the phishing probability independently; never substitute confidence.
            phishing_answer = dict(response['answers']['email_class'], choice='PHISHING')
            _, phishing_probability, _ = choice_answer({'answers': {'email_class': phishing_answer}}, 'email_class', CRITERIA)
            item = {
                'row_id': row['row_id'], 'dataset_label': '1', 'original_sha256': row['original_sha256'],
                'source_corpus': row.get('source_corpus', ''), 'baseline_prediction': '1' if choice == 'PHISHING' else '0',
                'baseline_status': 'ok', 'baseline_error': '',
                'decision_confidence': confidence if confidence is not None else '',
                'decision_probability_phishing': phishing_probability if phishing_probability is not None else '',
                'decision_probability_selected': probability if probability is not None else '',
                'victim_id': 'pplx_decider', 'victim_model': args.tool_id if args.transport == 'openwebui' else args.model,
                'victim_kind': 'decision', 'decision_evidence_json': json.dumps(evidence, sort_keys=True),
            }
            append_checkpoint(journal, item)
        results.append(item)
        atomic_csv(output, results, list(results[0]))
        print(f'{index}/{len(rows)} {row["row_id"]}: {item["baseline_prediction"]}', flush=True)
    summary = {'victim_id': 'pplx_decider', **metrics(rows, results)}
    atomic_csv(destination / 'metrics.csv', [summary], list(summary))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (RuntimeError, ValueError) as exc:
        print('Classification stopped: ' + str(exc) + '; no decision inferred. Completed checkpoints are preserved.', file=sys.stderr)
        sys.exit(1)
