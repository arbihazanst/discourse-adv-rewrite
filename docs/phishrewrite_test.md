# PhishRewrite label-1 classification test

This separate test uses the existing `PHISHING` / `NON_PHISHING` instructions
and structured Perplexity Decider response validation. Existing MeAJOR
launchers, configuration, prompts and workflow defaults are unchanged.

Source: https://zenodo.org/records/21018700, linked from
https://github.com/gaurangkatyal/phishrewrite. The v1.0 archive is stored under
`data/phishrewrite/`, with its Zenodo metadata. `prepare_phishrewrite.py` checks
the archive's published MD5 and records SHA-256 provenance.

The prepared `data/phishrewrite/label1.csv` contains all 5,390 original positive
emails, without sampling, language/length screening or prediction filtering.
It preserves published text and defanged URLs verbatim. Original IDs and the
4,312 train / 1,078 test membership are retained in separate columns. No
published rewrites are used. Any later training must respect those source splits.
Upstream documentation and license remain inside the archive.

## Initial test

Run from the project directory in PowerShell:

```powershell
.\RUN_PHISHREWRITE_PPLX_TEST.ps1
```

This tests the first 10 label-1 originals through the existing Open WebUI
PPLX tool at `llms.si-lab.org`. The launcher prompts for the API key with hidden
input if `OPENWEBUI_API_KEY` is not set. The GPT-OSS model routes the tool call;
only a verified structured PPLX tool result supplies the classification.
The test sends JSON Unicode escapes to the routing model to preserve mixed-script
lookalike characters. The decoded email remains unchanged, and the existing
exact-content validation still applies. This is opt-in for this test; other
Open WebUI callers retain their previous request encoding. Successful records
identify this encoding in their evidence. The latest server response is saved
as `last_response.json` (with any credential echo redacted); transport/tool
failures also create `last_error.json` without recording a prediction.
The tool ID identifies the configured server tool, not independently verified
model weights. This small sequential test is a connection check, not a
representative performance estimate.

For an authenticated direct SGLang endpoint:

```powershell
.\RUN_PHISHREWRITE_PPLX_TEST.ps1 -Transport direct -EndpointUrl 'https://YOUR-SERVER/v1/systemone' -Model 'YOUR-DECIDER-MODEL' -OutputDirectory outputs/phishrewrite_pplx_direct_test
```

The direct route requires the actual server URL/model ID and uses `PPLX_API_KEY`
or hidden input. No endpoint or model availability is inferred from the config.

To classify all positives after checking the connection:

```powershell
.\RUN_PHISHREWRITE_PPLX_TEST.ps1 -Limit 0 -OutputDirectory outputs/phishrewrite_pplx_all
```

Outputs include selected input, baseline predictions, per-row checkpoints,
connection/prompt/dataset provenance and metrics. Rerun the same command to
resume. Use a different output directory when changing the limit, data,
transport or model. Missing credentials, invalid tool evidence or connection
errors stop the run without inventing or checkpointing a prediction.

Interpret `1` as detected phishing and `0` as an original-email false negative.
No rewritten-email attack is performed by this test. Metrics are positive-only;
they do not measure benign false positives or attack success.

## Existing local baseline script

The prepared file also works with the unchanged local baseline script if its
configured Decider is running:

```powershell
python scripts/run_baseline.py --input data/phishrewrite/label1.csv --victims pplx_decider --label 1 --output-dir outputs/phishrewrite_pplx_local
```

The default local connection is `http://127.0.0.1:11435/v1/systemone`.
Its model tag comes from the existing config. On preparation, the input dry run
passed, but this server refused the connection and no API key was available for
the remote connection. Therefore preparation/offline checks are not live model
classification results.

## Observed live test (31 October 2026)

The Open WebUI connection subsequently produced eight verified decisions on the
first ten selected emails: seven PHISHING and one NON_PHISHING. Email nine
(`phishrewrite-nazario-4119`) stopped the run because the routing model changed
mixed-script Unicode characters in the subject before calling PPLX. Three
additional attempts using Unicode escapes also failed the unchanged input
validation. Unicode escaping is therefore not a verified fix for this case.
Email ten was not reached. No prediction from a changed input was accepted.

`outputs/phishrewrite_pplx_test/test_status.json` records this incomplete status;
`last_error.json` records mismatch hashes and `last_response.json` contains the
latest tool evidence. The baseline CSV has only the eight valid decisions.
Do not treat this as a completed ten-email evaluation or a rewrite attack test.
Completion requires the server to forward the original state unchanged; a
deterministic authenticated tool-execution route would avoid the routing model
regenerating email characters. Changing/normalizing the source text or weakening
the validation would change what is being tested and is not a fix.

On 2 November 2026 the direct SI-Lab service on local port 11435 became available.
The separate [SI-Lab launcher](silab_classification.md) completed all ten emails
without a routing model, including the Unicode example. Its results are stored
in `outputs/phishrewrite_silab_test/`; the incomplete Open WebUI run above remains
unchanged as a historical record.
