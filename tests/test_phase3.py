"""Tests for Phase 3 – Hyperparameter Tuning Module."""

import pytest
from phase3_hyperparameter.tuning_config import (
    TuningConfig,
    DEFAULT_EXPERIMENT_GRID,
    get_config_by_name,
)


class TestTuningConfig:
    def test_default_grid_has_entries(self):
        assert len(DEFAULT_EXPERIMENT_GRID) > 0

    def test_all_configs_have_required_fields(self):
        for cfg in DEFAULT_EXPERIMENT_GRID:
            assert cfg.name
            assert cfg.model
            assert isinstance(cfg.temperature, float)
            assert cfg.mode in ("binary", "non_binary", "cot", "multi_vuln")
            assert cfg.max_tokens > 0

    def test_get_config_by_name_found(self):
        cfg = DEFAULT_EXPERIMENT_GRID[0]
        found = get_config_by_name(cfg.name)
        assert found is not None
        assert found.name == cfg.name

    def test_get_config_by_name_not_found(self):
        assert get_config_by_name("nonexistent-config") is None

    def test_temperature_zero_and_one_configs_exist(self):
        temps = {cfg.temperature for cfg in DEFAULT_EXPERIMENT_GRID}
        assert 0.0 in temps
        assert 1.0 in temps

    def test_binary_and_nonbinary_modes_exist(self):
        modes = {cfg.mode for cfg in DEFAULT_EXPERIMENT_GRID}
        assert "binary" in modes
        assert "non_binary" in modes

    def test_custom_config_creation(self):
        cfg = TuningConfig(
            name="custom",
            model="gpt-4-turbo",
            temperature=0.5,
            mode="cot",
            max_tokens=1024,
            notes="Test config",
        )
        assert cfg.temperature == 0.5
        assert cfg.mode == "cot"
