# GPT-OSS demonstration rewrites

Run `RUN_GPTOSS_DEMO_REWRITE.ps1` from PowerShell in the project directory.
It requests the Open WebUI API key using hidden input and generates up to three
demonstrations. Use `-Limit 0` for all currently available detected positives.

The input is `data/phishrewrite/label1.csv`. Only emails with a successful
PHISHING prediction in `outputs/phishrewrite_pplx_test/pplx_decider_baseline.csv`
are selected. That baseline is currently partial: seven detected positives are
available. The rejected Unicode example and original false negative are excluded.

The script calls `openai/gpt-oss-120b` directly through
`https://llms.si-lab.org/api/chat/completions`, with tools disabled. GPT-OSS
generates the rewritten text; it does not route a PPLX classification call.
Existing classification launchers and criteria are unchanged.

Edit `templates/gptoss_demo_rewrite_prompt.txt` to adjust the demonstration prompt.
The default asks for text such as:

> TRAINING EXAMPLE: Hello, I am a phishing message. My link is [PHISHING_LINK].
> I am trying to trick you into sharing your account details. Do not click it
> or share information.

This is an illustrative output, not an observed model response. The output must
retain the training-example prefix and use placeholders instead of addresses.
Automatic checks do not replace a human content review.

`outputs/phishrewrite_gptoss_demo/rewrites.csv` pairs generated text with original
IDs and hashes. Per-row checkpoints support resume. Changing the model, prompt,
input or baseline requires a new output directory. Generation does not call the
victim classifier or compute attack success.

`dataset_label=1` describes the original email. The new `rewrite_label` and
`final_prediction` are empty, `review_status=unreviewed`, and
`valid_for_evasion_asr=0`: openly disclosed demonstrations remove deception and
must not be counted as intent-preserving phishing evasions.

To check preparation without sending requests:

```powershell
python scripts/rewrite_gptoss_demo.py --dry-run
```

For alternate input/baseline files, the Python script accepts `--input` and
`--baseline`. The baseline can be partial, but every included baseline row must
match the original ID, label and text hash.
