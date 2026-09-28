"""Verdent Platform — shared list-page query parsing.

Every table in the panel takes the same query string: `?q=` to search, `?page=`
and `?per_page=` to window, `?sort=` and `?dir=` to order. This module turns
that string into a validated `ListQuery` and back into URLs, so:

  * one place decides what a legal sort column is (an arbitrary `?sort=` fed
    straight into `order_by()` is SQL injection by another name — SQLAlchemy
    would quote it, but `?sort=nonexistent` is a 500 either way);
  * every table's "next page" link preserves the search term. Hand-built links
    that drop `q` are the classic pagination bug: search, click page 2, and the
    results silently un-filter;
  * the HTMX partial and the full page render from the same query, so a
    live-search request and a full reload cannot disagree.
"""

from dataclasses import dataclass, field
from urllib.parse import urlencode

from fastapi import Request

from admin_panel.pagination import Page, resolve_page

SORT_ASC = "asc"
SORT_DESC = "desc"


@dataclass(frozen=True)
class ListQuery:
    """A validated list-page query string."""

    q: str = ""
    page: Page = field(default_factory=lambda: resolve_page(None))
    sort: str = ""
    direction: str = SORT_ASC
    # Extra filters, e.g. {"status": "ACTIVE"}. Kept generic so each table can
    # carry its own without this module knowing about every page's fields.
    filters: dict[str, str] = field(default_factory=dict)

    def url(self, path: str, **overrides) -> str:
        """The URL for this query with some fields replaced.

        Used by the pager ("page 3") and the sort headers ("sort by date"), and
        it round-trips every other parameter — which is what keeps a search
        alive across a page change and a filter alive across a sort.
        """
        params = {
            "q": self.q,
            "sort": self.sort,
            "dir": self.direction,
            **self.filters,
        }
        if self.page.per_page != 50:
            params["per_page"] = str(self.page.per_page)

        for key, value in overrides.items():
            if value is None or value == "":
                params.pop(key, None)
            else:
                params[key] = str(value)

        # Drop empties so a clean URL stays clean (`/admin/nodes`, not
        # `/admin/nodes?q=&sort=&dir=asc`).
        clean = {k: v for k, v in params.items() if v}
        return f"{path}?{urlencode(clean)}" if clean else path

    def page_url(self, path: str, number: int) -> str:
        return self.url(path, page=number)

    def toggle_sort(self, path: str, column: str) -> str:
        """Sort by `column`, flipping direction if already sorted by it."""
        if self.sort == column:
            new_dir = SORT_DESC if self.direction == SORT_ASC else SORT_ASC
        else:
            new_dir = SORT_ASC
        return self.url(path, sort=column, dir=new_dir, page=None)

    def sort_indicator(self, column: str) -> str:
        """▼ / ▲ / empty — what the header shows next to a column name."""
        if self.sort != column:
            return ""
        return "▼" if self.direction == SORT_DESC else "▲"

    def is_desc(self, column: str) -> bool:
        return self.sort == column and self.direction == SORT_DESC

    def partial_params(self) -> str:
        """The query string for an HTMX request, without the page number.

        A live search must reset to page 1 — searching while on page 4 and
        landing on an empty page 4 is the bug this avoids.
        """
        params = {"q": self.q, **self.filters}
        clean = {k: v for k, v in params.items() if v}
        return urlencode(clean)


def parse_list_query(
    request: Request,
    *,
    allowed_sorts: tuple[str, ...] = (),
    default_sort: str = "",
    filter_keys: tuple[str, ...] = (),
) -> ListQuery:
    """Read the query string off a request into a validated ListQuery.

    `allowed_sorts` is enforced, not advisory: a sort column not in the tuple
    is replaced by `default_sort`. That is the difference between a typo in a
    header link being a no-op and being a 500 from `order_by(<bad column>)`.
    """
    params = request.query_params
    q = (params.get("q") or "").strip()

    sort = (params.get("sort") or "").strip()
    if sort and sort not in allowed_sorts:
        sort = default_sort
    if not sort:
        sort = default_sort

    direction = (params.get("dir") or "").strip().lower()
    if direction not in (SORT_ASC, SORT_DESC):
        direction = SORT_ASC

    filters = {}
    for key in filter_keys:
        value = (params.get(key) or "").strip()
        if value:
            filters[key] = value

    page = resolve_page(params.get("page"), params.get("per_page"))

    return ListQuery(q=q, page=page, sort=sort, direction=direction, filters=filters)


def is_htmx(request: Request) -> bool:
    """Whether this request came from HTMX.

    HTMX sends `HX-Request: true` on every request it makes. The list routes
    branch on it to return just the table partial instead of the whole page,
    which is what makes live search cheap: no layout, no sidebar, no nav.
    """
    return request.headers.get("HX-Request", "").lower() == "true"
