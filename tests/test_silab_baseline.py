import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from test_full_dataset import script
from phishbench.data import atomic_csv, read_csv
from phishbench.ollama_backend import Ollama
from phishbench.classification import CHAT_PROMPT


class TestSiLabBaseline(unittest.TestCase):
    def test_unicode_is_sent_directly_to_decision(self):
        calls = []
        def transport(endpoint, payload):
            calls.append((endpoint, payload))
            if endpoint == '/v1/systemone':
                return {'answers': {'email_class': {'choice': 'PHISHING'}}}
            return {'message': {'content': 'NON_PHISHING'}}
        client = Ollama('http://127.0.0.1:11435', transport=transport)
        text = '\u0420\u0391Y\u03a1\u0410\u053c account\nOriginal email'
        self.assertEqual(client.classify_decision('pplx-decider:latest', text).label, 1)
        self.assertEqual(calls[0][1]['state'], text)
        # Legacy chat-victim checks retained while the implementation is disabled.
        # self.assertEqual(client.classify_chat('qwen3.5:9b', text, CHAT_PROMPT).label, 0)
        # self.assertEqual(calls[1][1]['messages'][1]['content'], '<EMAIL_DATA>\n' + text + '\n</EMAIL_DATA>')
        self.assertFalse(hasattr(client, 'classify_chat'))
        self.assertEqual([endpoint for endpoint, _ in calls], ['/v1/systemone'])

    def test_limit_decision_model_resume_and_cohort_protection(self):
        runner = script('run_baseline')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source.csv'
            raw = [{'subject': 'Agenda', 'body': f'Office note {i}', 'label': label, 'source': 'test'}
                   for i, label in enumerate(('0', '1', '1', '1'))]
            atomic_csv(source, raw, list(raw[0]))
            config = root / 'models.json'
            config.write_text(json.dumps({'ollama_base_url': 'http://127.0.0.1:11434', 'victims': [
                {'id': 'test_decider', 'tag': 'test:latest', 'kind': 'decision', 'enabled': True}]}))
            output = root / 'out'
            args = ['baseline', '--input', str(source), '--config', str(config), '--output-dir', str(output),
                    '--victims', 'test_decider', '--decision-base-url', 'http://127.0.0.1:11435', '--limit', '2']
            with patch.object(sys, 'argv', args), patch.object(runner, 'Ollama') as backend:
                backend.return_value.classify_decision.return_value = SimpleNamespace(label=1, confidence=None, probabilities={})
                runner.main()
                backend.assert_called_once_with('http://127.0.0.1:11435')
                self.assertEqual(backend.return_value.classify_decision.call_count, 2)
                backend.return_value.classify_chat.assert_not_called()
                backend.reset_mock()
                runner.main()
                backend.return_value.classify_decision.assert_not_called()
            selected = (output / 'selected_input.csv').read_bytes()
            rows = read_csv(output / 'test_decider_baseline.csv')
            self.assertEqual(len(rows), 2)
            self.assertEqual({r['dataset_label'] for r in rows}, {'1'})
            with patch.object(sys, 'argv', args + ['--limit', '3']):
                with self.assertRaisesRegex(ValueError, 'Baseline changed'):
                    runner.main()
            self.assertEqual((output / 'selected_input.csv').read_bytes(), selected)

    def test_only_decisions_selected_and_legacy_chat_option_rejected(self):
        runner = script('run_baseline')
        config = json.loads(Path('config/models.json').read_text())
        selected = runner.select_victims(config)
        self.assertEqual({v['id'] for v in selected}, {'pplx_decider', 'nimble_9b', 'tev1_4b'})
        for victim in config['victims']:
            if victim['kind'] == 'chat':
                self.assertFalse(victim['enabled'])
                victim['enabled'] = True  # Cannot re-enable chat just by changing config.
                with self.assertRaisesRegex(ValueError, 'Only decision-model'):
                    runner.select_victims(config, [victim['id']])
        self.assertTrue(all(v['kind'] == 'decision' for v in runner.select_victims(config)))
        with self.assertRaisesRegex(ValueError, 'Unknown victim'):
            runner.select_victims(config, ['unknown'])
        self.assertEqual(runner.select_victims(config, ['clef_flash_9b'])[0]['kind'], 'decision')
        with patch.object(sys, 'argv', ['baseline', '--chat-model', 'legacy']), patch.object(runner, 'Ollama') as backend:
            with self.assertRaises(SystemExit) as error:
                runner.main()
            self.assertEqual(error.exception.code, 2)
            backend.assert_not_called()

    def test_model_check_rejects_unavailable_tag(self):
        checker = script('check_ollama')
        args = ['check', '--base-url', 'http://127.0.0.1:11435', '--model', 'missing:latest']
        with patch.object(sys, 'argv', args), patch.object(checker, 'Ollama') as client:
            client.return_value.tags.return_value = ['pplx-decider:latest']
            with self.assertRaisesRegex(ValueError, 'not listed'):
                checker.main()


if __name__ == '__main__':
    unittest.main()
