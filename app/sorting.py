"""Shared table sorting for server-paginated lists.

Columns are allowlisted per table so the query string never reaches SQL directly.
"""
from sqlalchemy import case, func

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def severity_rank_expr(column):
    """Order severities meaningfully (critical > info) instead of alphabetically."""
    return case(
        *[(func.lower(column) == name, rank) for name, rank in SEVERITY_RANK.items()],
        else_=0,
    )


def parse_sort(args, allowed, default, default_dir="asc"):
    """Return (column, direction). Invalid input falls back to the default."""
    column = args.get("sort") or default
    if column not in allowed:
        column = default
    direction = (args.get("dir") or default_dir).lower()
    if direction not in ("asc", "desc"):
        direction = "asc"
    return column, direction


def apply_sort(query, allowed, column, direction):
    """Order a query by an allowlisted column, nulls last in both directions."""
    expr = allowed[column]
    ordered = expr.asc() if direction == "asc" else expr.desc()
    return query.order_by(ordered.nullslast())


def sort_link_args(current_args, column):
    """Query args for a header link: keep filters, toggle direction, reset to page 1."""
    args = {k: v for k, v in current_args.items() if k not in ("page", "sort", "dir")}
    same = current_args.get("sort") == column
    prev_dir = (current_args.get("dir") or "asc").lower()
    new_dir = "desc" if same and prev_dir == "asc" else "asc"
    args.update({"sort": column, "dir": new_dir})
    return args
