import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_full_dataset import script
from phishbench.data import atomic_csv, read_csv


class TestGptossDemo(unittest.TestCase):
    def setUp(self):
        self.runner = script('rewrite_gptoss_demo')

    def test_final_content_only_and_label_links_truncation(self):
        text = 'TRAINING EXAMPLE: Hello, I am a phishing message. Do not click [PHISHING_LINK].'
        valid = {'choices': [{'finish_reason': 'stop', 'message': {'content': text, 'reasoning_content': 'Ignored'}}]}
        self.assertEqual(self.runner.demo_text(valid), text)
        for content, finish in [(text, 'length'), ('Hello', 'stop'), (text + ' hxxp://example.test', 'stop'), (None, 'stop')]:
            with self.subTest(content=content, finish=finish), self.assertRaises(ValueError):
                self.runner.demo_text({'choices': [{'finish_reason': finish, 'message': {'content': content}}]})

    def test_detected_positive_selection_resume_and_prompt_change(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original, baseline = [], []
            for index, prediction in enumerate(('0', '1', '')):
                text = f'Synthetic original {index}'
                row = {'row_id': str(index), 'dataset_label': '1', 'original_text': text,
                       'original_sha256': hashlib.sha256(text.encode()).hexdigest()}
                original.append(row)
                baseline.append({k: row[k] for k in ('row_id', 'dataset_label', 'original_sha256')})
                baseline[-1].update(baseline_prediction=prediction, baseline_status='ok' if prediction else 'error')
            atomic_csv(root / 'source.csv', original, list(original[0]))
            atomic_csv(root / 'baseline.csv', baseline, list(baseline[0]))
            prompt = root / 'prompt.txt'
            prompt.write_text('Write an explicitly labelled demonstration.', encoding='utf-8')
            args = ['rewrite', '--input', str(root / 'source.csv'), '--baseline', str(root / 'baseline.csv'),
                    '--prompt-file', str(prompt), '--output-dir', str(root / 'out')]
            response = {'choices': [{'finish_reason': 'stop', 'message': {
                'content': 'TRAINING EXAMPLE: This is a phishing example. Do not click [PHISHING_LINK].'}}]}
            with patch.object(sys, 'argv', args), patch.dict(os.environ, {'OPENWEBUI_API_KEY': 'test-secret'}), \
                    patch.object(self.runner, 'post_json', return_value=response) as request:
                self.assertEqual(self.runner.main(), 0)
                self.assertEqual(request.call_count, 1)
                payload = request.call_args.args[1]
                self.assertEqual(payload['tools'], [])
                self.assertEqual(payload['tool_ids'], [])
                self.assertEqual(payload['model'], 'openai/gpt-oss-120b')
                self.assertEqual(self.runner.main(), 0)
                self.assertEqual(request.call_count, 1)
                prompt.write_text('Changed prompt.', encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'prompt or model changed'):
                    self.runner.main()
            generated = read_csv(root / 'out/rewrites.csv')
            self.assertEqual([r['row_id'] for r in generated], ['1'])
            self.assertEqual(generated[0]['review_status'], 'unreviewed')
            self.assertEqual(generated[0]['final_prediction'], '')
            self.assertEqual(generated[0]['valid_for_evasion_asr'], '0')


if __name__ == '__main__':
    unittest.main()
