"""Checks that every registered pack has runtime policy assets."""

from driftarmor.checkov_runner import policies_root, policy_dirs_for_packs
from driftarmor.packs import PACKS
from driftarmor.report import default_citations_path, load_citations


def test_every_pack_has_a_policy_directory_with_python_checks():
    directories = policy_dirs_for_packs(PACKS)

    assert len(directories) == len(PACKS)
    for directory in directories:
        assert directory.is_relative_to(policies_root())
        assert any(path.name != "__init__.py" for path in directory.glob("*.py"))


def test_default_citations_asset_is_available():
    assert default_citations_path().is_file()
    assert load_citations()
