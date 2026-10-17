import os


# Third-party libraries Strix imports fetch remote files at import or first use.
# Keep them on their bundled copies so a scan host makes no calls the operator
# did not configure. Each is a default only; exporting the variable overrides it.
# - LiteLLM: model price map (feeds --max-budget) and Anthropic beta-header
#   config, otherwise pulled from BerriAI's GitHub ``main`` branch.
# - Hugging Face Hub: tokenizer downloads and usage telemetry. Token counting
#   falls back to a byte-length upper bound when a tokenizer is not bundled.
for _name, _value in (
    ("LITELLM_LOCAL_MODEL_COST_MAP", "True"),
    ("LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS", "True"),
    ("HF_HUB_OFFLINE", "1"),
    ("HF_HUB_DISABLE_TELEMETRY", "1"),
):
    os.environ.setdefault(_name, _value)
