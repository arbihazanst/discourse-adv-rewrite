# Decision-only victims and attacker model — 2026-11-02

- Set the rewrite attacker to `gpt-oss-120b-abliterated`; the demo script reads its default from `config/models.json`.
- Limit baseline execution and demo selection to decision-model victims. PPLX, Nimble and TEv1 remain enabled; CLEF remains opt-in.
- Preserve chat-victim code as comments and Qwen/Gemma configuration as disabled entries. Retain historical results and decision checkpoint compatibility.
- Keep the Open WebUI PPLX tool router separate from the attacker; update README and workflow notes.

# v4 — 2026-10-21

- MeAJOR now PRIMARY; original 191 MB CSV bundled for reproducibility.
- MeAJOR-specific streaming source audit; deterministic 1000 / 3000 selection with metadata retention and placeholder flags.
- Preserves label 0/1 and source provenance; langdetect + PPLX Ollama + JEV OpenRouter usability annotation for fixed cohort.
- Separate resumable per-row annotation and victim baseline; cross-model quality agreement, McNemar, optional SBERT/BLEU/ROUGE/Jaccard.
- GAN and Qwen method IDs supported in passive reviewed-candidate evaluation; no generation of phishing detector-evasion text.
- Windows BAT and Linux/macOS SH launchers; no Azure dependencies.
- Supersedes Alhuzali v3 primary dataset; Alhuzali optional independently prepared external validation.
