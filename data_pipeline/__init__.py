"""
data_pipeline — foundational data layer for the vulnerability detection framework.

The primary entry point is :mod:`data_pipeline.dataset_builder`, which downloads
smart-contract vulnerability datasets from Hugging Face and saves them into the
local ``data/raw/`` directory ready for the preprocessor pipeline.
"""
