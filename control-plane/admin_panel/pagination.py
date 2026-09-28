"""Verdent Platform — one pagination implementation for every table.

Nine list pages in the panel each need the same three things: a page number that
cannot be negative or absurd, a page size with a hard ceiling, and a total count
so the footer can say "1–50 از 312". Nine copies of that arithmetic is nine
chances to write `offset = page * per_page` instead of `(page - 1) * per_page`,
which silently skips the first page of every list.

The `PER_PAGE_MAX` ceiling is not cosmetic. `?per_page=1000000` against a
`usage_events`-sized table is a denial of service an unauthenticated-looking URL
can trigger, and the panel has no other rate limiting on its list pages.
"""

from dataclasses import dataclass

PER_PAGE_DEFAULT = 50
PER_PAGE_MAX = 200


@dataclass(frozen=True)
class Page:
    """A resolved page window plus the numbers a footer needs."""

    number: int
    per_page: int
    total: int

    @property
    def offset(self) -> int:
        return (self.number - 1) * self.per_page

    @property
    def limit(self) -> int:
        return self.per_page

    @property
    def first_index(self) -> int:
        """1-based index of the first row on this page (0 when empty)."""
        return self.offset + 1 if self.total else 0

    @property
    def last_index(self) -> int:
        return min(self.offset + self.per_page, self.total)

    @property
    def page_count(self) -> int:
        if self.per_page <= 0:
            return 1
        return max(1, (self.total + self.per_page - 1) // self.per_page)

    @property
    def has_prev(self) -> bool:
        return self.number > 1

    @property
    def has_next(self) -> bool:
        return self.number < self.page_count

    def window(self, *, span: int = 2) -> list[int]:
        """Page numbers to render around the current one, clamped to range."""
        if self.page_count <= 1:
            return [1]
        start = max(1, self.number - span)
        end = min(self.page_count, self.number + span)
        return list(range(start, end + 1))


def resolve_page(
    page: str | int | None,
    per_page: str | int | None = None,
    *,
    default_per_page: int = PER_PAGE_DEFAULT,
) -> Page:
    """Parse `?page=` / `?per_page=` into a safe Page. Never raises.

    A garbage value falls back to the default rather than 400ing: the query
    string is user-editable, and a page that 500s because someone hand-typed
    `?page=abc` is a worse experience than showing page 1.
    """
    number = _positive_int(page, 1)
    size = _positive_int(per_page, default_per_page)
    size = max(1, min(size, PER_PAGE_MAX))
    return Page(number=number, per_page=size, total=0)


def with_total(page: Page, total: int) -> Page:
    """Rebind a Page with its real total once the count query has run.

    Two-step because the count and the rows are separate queries, and the
    window must be clamped AFTER the total is known: `?page=999` on a 3-page
    table would otherwise render an empty table with no way back.
    """
    total = max(0, int(total))
    page_count = max(1, (total + page.per_page - 1) // page.per_page)
    return Page(
        number=min(page.number, page_count),
        per_page=page.per_page,
        total=total,
    )


def _positive_int(raw: str | int | None, default: int) -> int:
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default
