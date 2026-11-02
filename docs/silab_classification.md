# SI-Lab classification on port 11435

The user-confirmed connection is `http://127.0.0.1:11435`, with no API key.
Keep the SI-Lab connection/tunnel active. Victim classification now uses decision
models only. The server's `/api/tags` endpoint was verified on 2 November 2026;
the enabled decision victims are:

| Victim ID | Model tag | Classification route |
| --- | --- | --- |
| `pplx_decider` | `pplx-decider:latest` | `/v1/systemone` |
| `nimble_9b` | `nimble:9b` | `/v1/systemone` |
| `tev1_4b` | `tev1:4b` | `/v1/systemone` |

Model-list presence is an availability check, not an inference result for every
model. The launcher preserves the existing PHISHING/NON_PHISHING instructions,
numeric labels, per-row checkpoints and original text. It does not use an
Open WebUI routing model, rewrite the email, or run an attacker.

## Run from the project directory

The default is a ten-email PPLX connection test on original PhishRewrite label-1
emails, stored separately from previous results:

```powershell
.\RUN_BASELINE_SILAB.ps1
```

The launcher verifies the exact model tag, invokes the existing baseline script,
and generates metrics on the same selected input. For the ten-email test:

- `outputs/phishrewrite_silab_test/selected_input.csv`: selected original rows.
- `outputs/phishrewrite_silab_test/pplx_decider_baseline.csv`: actual predictions.
- `outputs/phishrewrite_silab_test/metrics.csv`: positive-only detection results.
- Companion manifest and checkpoint files: run identity and resume state.

To classify all 5,390 original positive emails with PPLX:

```powershell
.\RUN_BASELINE_SILAB.ps1 -Limit 0 -OutputDirectory outputs/phishrewrite_silab_pplx_all
```

To test all three configured enabled decision victims on ten emails:

```powershell
.\RUN_BASELINE_SILAB.ps1 -Victims pplx_decider,nimble_9b,tev1_4b -OutputDirectory outputs/phishrewrite_silab_decisions
```

Use configured victim IDs for decision models. `-ChatModel` and baseline
`--chat-model` are disabled. The Qwen/Gemma configuration entries remain with
`enabled: false`; their selection is rejected even if that flag is changed.
The old chat-victim implementation is retained as comments in the backend,
baseline script and launcher. Historical chat results are not deleted.

`-InputCsv` can select another prepared cohort. The original MeAJOR launchers
also select only enabled decision victims. `-DryRun` checks local preparation
without contacting the server. The Python baseline's new `--limit` defaults to
zero (all selected rows), preserving its old default behavior.

Use a fresh output directory when changing the model, endpoint, data or limit.
Rerun the same command to resume the same experiment. When using a row limit,
calculate metrics against `selected_input.csv`, not the complete source dataset.
These positive-only tests cannot measure false positives on benign email or
rewrite attack success.

To list model tags without sending any emails:

```powershell
python scripts/check_ollama.py --base-url http://127.0.0.1:11435
```

API references: [Ollama chat](https://docs.ollama.com/api/chat) and
[model listing](https://docs.ollama.com/api/tags). The `/v1/systemone` decision
route is the existing deployment-specific interface used by this project;
it is not assumed to exist on every standard Ollama installation.

## Verified PPLX run

The direct ten-email run on 2 November 2026 completed with ten valid decisions:
eight PHISHING and two NON_PHISHING. The previously blocked Unicode example
`phishrewrite-nazario-4119` received a PHISHING decision through the direct route.
Results are in `outputs/phishrewrite_silab_test/`; the older incomplete Open WebUI
run is preserved separately. This small connection test is not a representative
estimate of full-dataset performance, and the two original-email false negatives
are not rewrite attack successes.
