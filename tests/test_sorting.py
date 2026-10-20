"""Shared sort helper: allowlisting, direction, null handling, and rank ordering."""
import pytest
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.sorting import (SEVERITY_RANK, apply_sort, parse_sort, severity_rank_expr,
                         sort_link_args)

Base = declarative_base()


class Row(Base):
    __tablename__ = "rows"
    id = Column(Integer, primary_key=True)
    name = Column(String(50))
    score = Column(Integer, nullable=True)
    severity = Column(String(20), nullable=True)


ALLOWED = {"name": Row.name, "score": Row.score, "severity": severity_rank_expr(Row.severity)}


@pytest.fixture()
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add_all([
        Row(id=1, name="beta", score=5, severity="low"),
        Row(id=2, name="Alpha", score=None, severity="critical"),
        Row(id=3, name="gamma", score=20, severity=None),
        Row(id=4, name="delta", score=1, severity="medium"),
    ])
    s.commit()
    yield s
    s.close()


def test_parse_sort_uses_default_for_missing_or_unknown_column():
    assert parse_sort({}, ALLOWED, default="score", default_dir="desc") == ("score", "desc")
    assert parse_sort({"sort": "password"}, ALLOWED, default="name", default_dir="asc") == ("name", "asc")


def test_parse_sort_rejects_bad_direction_and_keeps_column():
    assert parse_sort({"sort": "name", "dir": "sideways"}, ALLOWED,
                      default="score", default_dir="desc") == ("name", "asc")


def test_apply_sort_ascending_text_is_case_insensitive(session):
    query = session.query(Row)
    rows = apply_sort(query, ALLOWED, "name", "asc").all()
    assert [r.name.lower() for r in rows] == ["alpha", "beta", "delta", "gamma"]


def test_apply_sort_numeric_nulls_last_in_both_directions(session):
    asc = [r.score for r in apply_sort(session.query(Row), ALLOWED, "score", "asc").all()]
    desc = [r.score for r in apply_sort(session.query(Row), ALLOWED, "score", "desc").all()]
    assert asc == [1, 5, 20, None]
    assert desc == [20, 5, 1, None]


def test_severity_sorts_by_rank_not_alphabetically(session):
    rows = apply_sort(session.query(Row), ALLOWED, "severity", "desc").all()
    ranked = [r.severity for r in rows if r.severity]
    assert ranked == ["critical", "medium", "low"]
    assert rows[-1].severity is None


def test_severity_rank_table_is_ordered():
    assert SEVERITY_RANK["critical"] > SEVERITY_RANK["high"] > SEVERITY_RANK["medium"] \
        > SEVERITY_RANK["low"] > SEVERITY_RANK["info"]


def test_sort_link_args_keep_filters_and_reset_page_direction():
    out = sort_link_args({"q": "x", "page": "3", "sort": "name", "dir": "asc"}, "score")
    assert out["q"] == "x"
    assert out["sort"] == "score"
    assert out["dir"] == "asc"
    assert "page" not in out
