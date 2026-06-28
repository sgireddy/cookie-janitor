"""Cookie classification via the Open Cookie Database.

The Open Cookie Database (https://github.com/jkwakman/Open-Cookie-Database)
is a community-maintained CSV with columns:

    ID, Platform, Category, Cookie / Data Key name, Domain,
    Description, Retention period, Data Controller, User Privacy & GDPR
    Rights Portals, Wildcard match

We only need ``Cookie name``, ``Domain``, ``Category``, and
``Description``. We load the CSV into an in-memory index keyed on
exact cookie name, plus a small set of well-known wildcard prefixes
(``_ga*`` → all Google Analytics IDs).

The CSV is loaded from ``data/`` (a pinned snapshot) or from the user's
cache directory if they have run ``update-lists``. The runtime verifies
the file's sha256 against a manifest before loading.
"""

from __future__ import annotations

import csv
import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

from cookie_janitor.model.cookie import Category

log = logging.getLogger(__name__)


_CATEGORY_MAP: dict[str, Category] = {
    "functional": Category.FUNCTIONAL,
    "strictly necessary": Category.FUNCTIONAL,
    "performance": Category.PERFORMANCE,
    "analytics": Category.ANALYTICS,
    "marketing": Category.MARKETING,
    "advertising": Category.MARKETING,
    "targeting": Category.MARKETING,
}


@dataclass(frozen=True, slots=True)
class CookieDescription:
    """A row from the Open Cookie Database, normalized."""

    name: str
    domain: str  # may be "" if not specified
    category: Category
    description: str


@dataclass(frozen=True, slots=True)
class CookieDatabase:
    """In-memory lookup table.

    Lookups are O(1) for exact matches and O(prefixes) for the small
    wildcard set. Built once per process; safe to share across threads.
    """

    by_exact_name: dict[str, list[CookieDescription]]
    by_prefix: dict[str, list[CookieDescription]]

    def lookup(self, name: str, domain: str) -> CookieDescription | None:
        """Return the best matching description, or ``None``.

        Best = exact (name, domain) > exact name with any domain > prefix
        (name has a known wildcard prefix).
        """
        if not name:
            return None

        exact = self.by_exact_name.get(name)
        if exact:
            # Prefer a row whose domain matches as a suffix of cookie.domain.
            dom = (domain or "").lstrip(".").lower()
            for d in exact:
                rd = d.domain.lstrip(".").lower()
                if rd and (dom == rd or dom.endswith("." + rd)):
                    return d
            return exact[0]

        for prefix, rows in self.by_prefix.items():
            if name.startswith(prefix):
                return rows[0]

        return None


def load_database(csv_path: Path, *, expected_sha256: str | None = None) -> CookieDatabase:
    """Load and return a CookieDatabase from a CSV file.

    If ``expected_sha256`` is provided, the file is hashed and verified
    before loading. A mismatch raises ``ValueError`` (we fail closed:
    refusing to load is much better than loading attacker-controlled
    classification data — see THREAT_MODEL TH-4).
    """
    if expected_sha256:
        actual = _sha256_of(csv_path)
        if actual != expected_sha256:
            raise ValueError(
                f"Cookie database hash mismatch for {csv_path}: "
                f"expected {expected_sha256}, got {actual}. "
                f"Refusing to load (see THREAT_MODEL TH-4)."
            )

    by_exact: dict[str, list[CookieDescription]] = {}
    by_prefix: dict[str, list[CookieDescription]] = {}

    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            name = (row.get("Cookie / Data Key name") or row.get("Cookie") or "").strip()
            if not name:
                continue
            domain = (row.get("Domain") or "").strip()
            cat_raw = (row.get("Category") or "").strip().lower()
            description = (row.get("Description") or "").strip()
            cat = _CATEGORY_MAP.get(cat_raw, Category.UNKNOWN)
            desc = CookieDescription(
                name=name, domain=domain, category=cat, description=description
            )
            if name.endswith("*"):
                by_prefix.setdefault(name[:-1], []).append(desc)
            else:
                by_exact.setdefault(name, []).append(desc)

    log.info(
        "Loaded cookie database: %d exact entries, %d wildcard prefixes",
        sum(len(v) for v in by_exact.values()),
        len(by_prefix),
    )
    return CookieDatabase(by_exact_name=by_exact, by_prefix=by_prefix)


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
