import importlib.resources

from cookie_janitor.classify.cookie_db import load_database
from cookie_janitor.model.cookie import Category


def test_bundled_seed_loads_and_classifies_common_cookies():
    files = importlib.resources.files("cookie_janitor.data")
    seed = files / "cookie_db_seed.csv"
    with importlib.resources.as_file(seed) as p:
        db = load_database(p)

    # Google session cookies should be Functional (must keep).
    desc = db.lookup("SID", ".google.com")
    assert desc is not None
    assert desc.category is Category.FUNCTIONAL

    # GA cookie is Analytics regardless of host.
    desc = db.lookup("_ga", "some-random-site.test")
    assert desc is not None
    assert desc.category is Category.ANALYTICS

    # GA4 wildcard.
    desc = db.lookup("_ga_ABC123", "some-random-site.test")
    assert desc is not None
    assert desc.category is Category.ANALYTICS


def test_hash_mismatch_refuses_to_load(tmp_path):
    import pytest

    csv = tmp_path / "x.csv"
    csv.write_text("Cookie / Data Key name,Category\nfoo,Functional\n")
    with pytest.raises(ValueError, match="hash mismatch"):
        load_database(csv, expected_sha256="0" * 64)
