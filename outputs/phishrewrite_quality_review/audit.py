"""Read-only audit of the local PhishRewrite release and prepared originals.

Run from the repository root: python -B outputs/phishrewrite_quality_review/audit.py
Writes only an aggregate audit.json beside this script; never modifies inputs.
"""
import csv
import hashlib
import io
import json
import re
import unicodedata
import zipfile
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def normalized(text):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', text)).strip().casefold()


def profile(rows, text_key, id_key, label_key, split_key):
    groups = defaultdict(list)
    normalized_groups = defaultdict(list)
    for row in rows:
        groups[sha(row[text_key])].append(row)
        normalized_groups[sha(normalized(row[text_key]))].append(row)
    return {
        'rows': len(rows),
        'columns': list(rows[0]) if rows else [],
        'labels': dict(Counter(r[label_key] for r in rows)),
        'splits': dict(Counter(r[split_key] for r in rows)),
        'split_label_counts': dict(Counter(r[split_key] + '/' + r[label_key] for r in rows)),
        'duplicate_id_excess': len(rows) - len({r[id_key] for r in rows}),
        'empty_text_rows': sum(not r[text_key].strip() for r in rows),
        'exact_duplicate_text_excess': len(rows) - len(groups),
        'normalized_duplicate_text_excess': len(rows) - len(normalized_groups),
        'exact_cross_split_text_groups': sum(len({r[split_key] for r in group}) > 1 for group in groups.values()),
        'normalized_cross_split_text_groups': sum(len({r[split_key] for r in group}) > 1 for group in normalized_groups.values()),
        'exact_text_conflicting_label_groups': sum(len({r[label_key] for r in group}) > 1 for group in groups.values()),
        'normalized_text_conflicting_label_groups': sum(len({r[label_key] for r in group}) > 1 for group in normalized_groups.values()),
    }


def main():
    root = Path(__file__).resolve().parents[2]
    folder = root / 'data/phishrewrite'
    archive = folder / 'phishrewrite-benchmark-v1.0.zip'
    raw_archive = archive.read_bytes()
    record = json.loads((folder / 'zenodo_record.json').read_text(encoding='utf-8'))
    provenance = json.loads((folder / 'label1.csv.source.json').read_text(encoding='utf-8'))
    published = next(f for f in record['files'] if f['key'] == archive.name)
    csv.field_size_limit(2**31-1)
    with zipfile.ZipFile(archive) as z:
        emails = list(csv.DictReader(io.TextIOWrapper(z.open('data/emails.csv'), encoding='utf-8-sig')))
        rewrites = list(csv.DictReader(io.TextIOWrapper(z.open('data/rewrites.csv'), encoding='utf-8-sig')))
    with (folder / 'label1.csv').open(encoding='utf-8-sig', newline='') as f:
        prepared = list(csv.DictReader(f))
    originals = {r['id']: r for r in emails}
    # Rewrites use source-local original_id, NOT the unified emails.id.
    source_originals = {(r['source'], r['original_id']): r for r in emails}
    positives = [r for r in emails if r['label'] == '1']
    mismatches = []
    for row in prepared:
        source = originals.get(row['row_id'].removeprefix('phishrewrite-'))
        if source is None or any((row['original_text'] != source['text'],
                                 row['original_sha256'] != sha(row['original_text']),
                                 row['source_split'] != source['split'],
                                 row['dataset_label'] != source['label'],
                                 row['subject'] != source['subject'],
                                 row['body'] != source['body'])):
            mismatches.append(row['row_id'])
    report = {
        'checked_at': datetime.now(ZoneInfo('Asia/Jakarta')).isoformat(),
        'release': 'PhishRewrite v1.0',
        'source_url': 'https://zenodo.org/records/21018700',
        'documentation': ['https://github.com/gaurangkatyal/phishrewrite/blob/main/README.md',
                          'https://github.com/gaurangkatyal/phishrewrite/blob/main/LIMITATIONS.md',
                          'https://github.com/gaurangkatyal/phishrewrite/blob/main/src/release.py'],
        'checks': {
            'archive_matches_saved_published_md5': 'md5:' + hashlib.md5(raw_archive).hexdigest() == published['checksum'],
            'archive_matches_sidecar_sha256': hashlib.sha256(raw_archive).hexdigest() == provenance['archive_sha256'],
            'prepared_file_matches_sidecar_sha256': hashlib.sha256((folder / 'label1.csv').read_bytes()).hexdigest() == provenance['output_sha256'],
            'prepared_contains_exactly_all_positive_ids': {r['row_id'] for r in prepared} == {'phishrewrite-' + r['id'] for r in positives},
            'prepared_source_mismatch_rows': len(mismatches),
        },
        'emails': profile(emails, 'text', 'id', 'label', 'split'),
        'positive_originals': profile(positives, 'text', 'id', 'label', 'split'),
        'prepared': profile(prepared, 'original_text', 'row_id', 'dataset_label', 'source_split'),
        'source_label_counts': dict(Counter(r['source'] + '/' + r['label'] for r in emails)),
        'duplicate_source_original_id_excess': len(emails) - len(source_originals),
        'positive_missing_subject': sum(not r['subject'].strip() for r in positives),
        'positive_missing_body': sum(not r['body'].strip() for r in positives),
        'positive_missing_body_by_split': dict(Counter(r['split'] for r in positives if not r['body'].strip())),
        'positive_with_defanged_url_marker': sum(bool(re.search(r'hxxps?://|www\[\.\]', r['text'], re.I)) for r in positives),
        'rewrites': {
            'rows': len(rewrites), 'columns': list(rewrites[0]),
            'unique_original_ids': len({r['original_id'] for r in rewrites}),
            'models': dict(Counter(r['model'] for r in rewrites)),
            'severities': dict(Counter(r['severity'] for r in rewrites)),
            'join_key': '(source, original_id) in emails.csv and rewrites.csv',
            'missing_original_ids': sum((r['source'], r['original_id']) not in source_originals for r in rewrites),
            'not_test_positive': sum(source_originals.get((r['source'], r['original_id']), {}).get('split') != 'test' or source_originals.get((r['source'], r['original_id']), {}).get('label') != '1' for r in rewrites),
            'empty_text_rows': sum(not r['rewrite_text'].strip() for r in rewrites),
            'retained_urls_strict': dict(Counter(r['retained_urls_strict'] for r in rewrites)),
            'refused': dict(Counter(r['refused'] for r in rewrites)),
        },
        'limits': ['Normalized checks cover NFKC, whitespace, and case only; no semantic near-duplicate detection.',
                   'No independent per-email human phishing-label adjudication.',
                   'No model inference, no URL visits, no test of pretraining contamination.',
                   'Published checksum is from the saved Zenodo metadata; current GitHub documentation was inspected separately.'],
    }
    destination = Path(__file__).with_name('audit.json')
    destination.write_text(json.dumps(report, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
