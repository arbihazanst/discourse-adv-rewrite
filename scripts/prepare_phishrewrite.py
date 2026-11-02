#!/usr/bin/env python3
"""Adapt original PhishRewrite label-1 emails without changing baseline defaults."""
import argparse
import csv
import hashlib
import io
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phishbench.data import atomic_csv, atomic_json, hash_file, parse_gold


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', default='data/phishrewrite/phishrewrite-benchmark-v1.0.zip')
    parser.add_argument('--record', default='data/phishrewrite/zenodo_record.json')
    parser.add_argument('--output', default='data/phishrewrite/label1.csv')
    args = parser.parse_args()
    archive = Path(args.archive)
    record = json.loads(Path(args.record).read_text(encoding='utf-8'))
    entry = next(f for f in record['files'] if f['key'] == archive.name)
    if 'md5:' + hashlib.md5(archive.read_bytes()).hexdigest() != entry['checksum']:
        raise ValueError('Archive does not match the Zenodo checksum')
    csv.field_size_limit(2**31-1)
    with zipfile.ZipFile(archive) as bundle:
        members = [n for n in bundle.namelist() if n.endswith('/data/emails.csv') or n == 'data/emails.csv']
        if len(members) != 1:
            raise ValueError('Expected exactly one original emails.csv')
        with bundle.open(members[0]) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding='utf-8-sig', newline=''))
            required = {'id', 'label', 'source', 'split', 'original_id', 'subject', 'body', 'text'}
            if not required.issubset(reader.fieldnames or []):
                raise ValueError('Unexpected PhishRewrite schema')
            source = list(reader)
    selected = []
    seen = set()
    for index, email in enumerate(source):
        if None in email or any(email[k] is None for k in required):
            raise ValueError('Malformed source record')
        if not email['id'] or email['id'] in seen:
            raise ValueError('Missing or duplicate original email ID')
        seen.add(email['id'])
        if parse_gold(email['label']) != 1:
            continue
        if not email['text'].strip() or email['split'] not in ('train', 'test'):
            raise ValueError('Empty email or invalid split')
        selected.append({
            'row_id': 'phishrewrite-' + email['id'], 'dataset_label': '1',
            'original_text': email['text'],
            'original_sha256': hashlib.sha256(email['text'].encode('utf-8')).hexdigest(),
            'source_dataset': 'phishrewrite_v1.0', 'source_corpus': email['source'],
            'source_index': str(index), 'source_original_id': email['original_id'],
            'source_split': email['split'], 'subject': email['subject'], 'body': email['body'],
            'url_representation': 'defanged_as_released',
        })
    if not selected:
        raise ValueError('No label-1 emails found')
    atomic_csv(args.output, selected, list(selected[0]))
    summary = {
        'source_url': 'https://zenodo.org/records/21018700',
        'archive_sha256': hash_file(archive), 'archive_md5': entry['checksum'],
        'archive_member': members[0], 'output_sha256': hash_file(args.output),
        'source_rows': len(source), 'selected_rows': len(selected), 'label': 1,
        'split_counts': dict(Counter(r['source_split'] for r in selected)),
        'duplicate_text_excess': len(selected) - len({r['original_sha256'] for r in selected}),
        'selection': 'All original label-1 emails; no length, language, prediction or split filtering.',
        'text_policy': 'Published text and defanged URLs preserved verbatim. No published rewrites included.',
    }
    atomic_json(str(args.output) + '.source.json', summary)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
