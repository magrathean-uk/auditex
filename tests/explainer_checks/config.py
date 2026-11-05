"""Frozen checker thresholds; no paths, environment discovery or runtime imports."""

LIMITS = {"explanation_words": 80, "explanation_sentences": 3, "max_steps": 6,
          "step_words": 30, "max_output_tokens": 450, "chars_per_token": 4.25}
PARAPHRASE_THETA = 0.85
PARAPHRASE_MIN_TOKENS = 7
PARAPHRASE_WINDOW_UNITS = 3
PARAPHRASE_MAX_NOVEL = 1
