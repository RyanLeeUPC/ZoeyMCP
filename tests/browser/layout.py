"""Geometry checks of what a page shows, read from the rendered layout, never from screenshots
(which move with fonts and browser versions; D-222).

M6's confirm dialog once squeezed every value to one character a line behind a label wider than
the dialog (manual item 20): a CSS rule that reads right can still lay out wrong, and only the
browser's boxes show it.
"""

from __future__ import annotations

from typing import Any

from playwright.sync_api import Locator, Page


def overflow(page: Page, selector: str = "body") -> dict[str, Any]:
    """The element's content width and its box's (``scrollWidth``, ``clientWidth``)."""
    found: dict[str, Any] = page.locator(selector).first.evaluate(
        "(element) => ({scroll: element.scrollWidth, client: element.clientWidth})"
    )
    return found


def assert_no_horizontal_overflow(page: Page, selector: str = "body") -> None:
    """Nothing in the element is wider than the element: no sideways scrolling."""
    found = overflow(page, selector)
    assert found["scroll"] <= found["client"], found


def width_share(inner: Locator, outer: Locator) -> float:
    """``inner``'s width as a share of ``outer``'s, from their rendered boxes."""
    inner_box, outer_box = inner.bounding_box(), outer.bounding_box()
    assert inner_box is not None, "not rendered"
    assert outer_box is not None, "not rendered"
    return inner_box["width"] / outer_box["width"]


def line_count(locator: Locator) -> int:
    """How many lines the element's text takes as laid out (its client rects' distinct tops)."""
    tops: list[float] = locator.evaluate(
        "(element) => {"
        " const range = document.createRange(); range.selectNodeContents(element);"
        " return Array.from(range.getClientRects(), (rect) => Math.round(rect.top)); }"
    )
    return len(set(tops))
