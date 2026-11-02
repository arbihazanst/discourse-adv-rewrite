import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_full_dataset import script
from phishbench.data import atomic_csv, read_csv
from phishbench.classification import INSTRUCTIONS, CRITERIA
from phishbench import openwebui_decider as webui


class TestPhishRewriteDecision(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = script('test_phishrewrite_decider')
        self.dataset = self.root / 'input.csv'
        rows = []
        for index, label in enumerate(('0', '1', '1')):
            text = f'Synthetic fixture {index}'
            rows.append({'row_id': str(index), 'dataset_label': label, 'original_text': text,
                         'original_sha256': hashlib.sha256(text.encode()).hexdigest(), 'source_corpus': 'fixture'})
        atomic_csv(self.dataset, rows, list(rows[0]))
        self.args = ['test', '--input', str(self.dataset), '--output-dir', str(self.root / 'out'), '--limit', '0']

    def answer(self, choice):
        return {'answers': {'email_class': {'choice': choice, 'probabilities': {'PHISHING': .4, 'NON_PHISHING': .6},
                                            'confidence': .2}}}, {'decision_tool_source': 'verified_fixture'}

    def test_only_positives_same_criteria_resume_and_metric_denominator(self):
        with patch.object(sys, 'argv', self.args), patch.dict(os.environ, {'OPENWEBUI_API_KEY': 'test-secret'}), \
                patch.object(self.runner, 'request_decision', side_effect=[self.answer('PHISHING'), self.answer('NON_PHISHING')]) as request:
            self.assertEqual(self.runner.main(), 0)
            self.assertEqual(request.call_count, 2)
            payload = request.call_args_list[0].args[3]
            self.assertEqual(payload['state'], 'Synthetic fixture 1')
            self.assertEqual(payload['questions']['email_class'], {'type': 'choice', 'instructions': INSTRUCTIONS, 'criteria': CRITERIA})
            request.reset_mock()
            self.assertEqual(self.runner.main(), 0)
            request.assert_not_called()
        results = read_csv(self.root / 'out/pplx_decider_baseline.csv')
        self.assertEqual([r['baseline_prediction'] for r in results], ['1', '0'])
        self.assertEqual(results[0]['decision_probability_phishing'], '0.4')
        summary = read_csv(self.root / 'out/metrics.csv')[0]
        self.assertEqual((summary['tp'], summary['fn'], summary['n_total']), ('1', '1', '2'))
        self.assertNotIn('test-secret', (self.root / 'out/pplx_decider_baseline.csv.run.json').read_text())

    def test_chat_text_is_not_a_decision_and_cannot_commit(self):
        with patch.object(sys, 'argv', self.args), patch.dict(os.environ, {'OPENWEBUI_API_KEY': 'test-secret'}), \
                patch.object(self.runner, 'request_decision', return_value=({'choices': [{'text': 'PHISHING'}]}, {})):
            with self.assertRaisesRegex(ValueError, 'Missing/invalid structured'):
                self.runner.main()
        self.assertFalse((self.root / 'out/pplx_decider_baseline.csv.checkpoint.jsonl').exists())

    def test_direct_transport_and_changed_run_rejected(self):
        args = self.args + ['--transport', 'direct', '--endpoint-url', 'https://example.org/v1/systemone', '--model', 'test-decider']
        with patch.object(sys, 'argv', args), patch.dict(os.environ, {'PPLX_API_KEY': 'test-secret'}), \
                patch.object(self.runner, 'post_json', return_value=self.answer('PHISHING')[0]) as request:
            self.assertEqual(self.runner.main(), 0)
            self.assertEqual(request.call_args.args[1]['model'], 'test-decider')
        with patch.object(sys, 'argv', args + ['--limit', '1']), patch.dict(os.environ, {'PPLX_API_KEY': 'test-secret'}):
            with self.assertRaisesRegex(ValueError, 'Run settings changed'):
                self.runner.main()

    def test_unicode_escaping_preserves_original_and_rejects_transliteration(self):
        expected = {'state': '\u0420\u0391Y\u03a1\u0410\u053c account', 'questions': {
            'email_class': {'type': 'choice', 'instructions': INSTRUCTIONS, 'criteria': CRITERIA}}}
        result = self.answer('PHISHING')[0]
        response = {'sources': [{'tool_result': True,
            'source': {'name': 'server:pplxdeciderflash/systemone'},
            'metadata': [{'parameters': expected}], 'document': [json.dumps(result)]}]}
        with patch.dict(os.environ, {'OPENWEBUI_API_KEY': 'test-secret'}), \
                patch.object(webui, 'post_json', return_value=response) as request:
            actual, evidence = webui.request_decision('https://example.org', 'router',
                'server:pplxdeciderflash', expected, escape_unicode=True, tool_attempts=1)
            encoded = request.call_args.args[1]['messages'][1]['content']
            self.assertTrue(encoded.isascii())
            self.assertEqual(json.loads(encoded), expected)
            self.assertEqual(actual, result)
            self.assertEqual(evidence['decision_state_comparison'], 'exact')
            response['sources'][0]['metadata'] = [{'parameters': {**expected, 'state': 'PAYPAL account'}}]
            with self.assertRaises(webui.ToolArgumentsMismatch):
                webui.request_decision('https://example.org', 'router',
                    'server:pplxdeciderflash', expected, escape_unicode=True, tool_attempts=1)


if __name__ == '__main__':
    unittest.main()
