# Tests for the CLI row-filter expression grammar (volatility3.cli.text_filter)
#
# These require no memory image, but the conftest --volatility option must
# still be supplied for collection to succeed.

import pytest

from volatility3.cli import text_filter
from volatility3.framework import exceptions
from volatility3.framework.interfaces.renderers import Column


class FakeTreeGrid:
    """Minimal stand-in exposing the columns a CLIFilter resolves against."""

    def __init__(self, names):
        self.columns = [Column(name, str) for name in names]


def make_filter(grid, *filters):
    return text_filter.CLIFilter(grid, list(filters))


def kept_rows(cli_filter, rows):
    """Returns the rows the filter would keep (filter() == True means drop)."""
    return [row for row in rows if not cli_filter.filter(row)]


#
# Column resolution
#


def test_exact_column_name_wins_over_substring_matches():
    # "pid" is a substring of both PID and PPID, but exactly equals PID
    grid = FakeTreeGrid(["PID", "PPID", "Name"])
    cli_filter = make_filter(grid, "pid,4")
    assert cli_filter._filters[0].column_num == 0


def test_unique_substring_resolves_to_its_column():
    grid = FakeTreeGrid(["PID", "Name", "CreateTime"])
    cli_filter = make_filter(grid, "time,2021")
    assert cli_filter._filters[0].column_num == 2


def test_column_resolution_is_case_insensitive():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, "NAME,svchost")
    assert cli_filter._filters[0].column_num == 1


def test_ambiguous_column_name_is_an_error_not_a_guess():
    # "pi" is a substring of both PID and PPID; previously the first hit
    # won silently, so reordered columns flipped the behaviour
    grid = FakeTreeGrid(["PID", "PPID", "Name"])
    with pytest.raises(exceptions.RenderException, match="ambiguous"):
        make_filter(grid, "pi,4")


def test_ambiguity_is_detected_regardless_of_column_order():
    for names in (["PID", "PPID", "Name"], ["PPID", "Name", "PID"]):
        grid = FakeTreeGrid(names)
        with pytest.raises(exceptions.RenderException):
            make_filter(grid, "pi,4")


def test_unambiguous_expression_filters_identically_regardless_of_column_order():
    # The same logical grid in two column orders: the filter must follow
    # the column name, never the position
    grids_and_rows = [
        (["PID", "PPID", "Name"], [["4", "0", "system"], ["100", "4", "svchost.exe"]]),
        (["PPID", "Name", "PID"], [["0", "system", "4"], ["4", "svchost.exe", "100"]]),
    ]
    for names, rows in grids_and_rows:
        cli_filter = make_filter(FakeTreeGrid(names), "PPID,4")
        kept = kept_rows(cli_filter, rows)
        assert len(kept) == 1
        assert "svchost.exe" in kept[0]


def test_unknown_column_name_is_an_error_not_all_columns():
    # Previously a miss silently fell back to matching every column,
    # which could keep rows the filter was meant to drop
    grid = FakeTreeGrid(["PID", "Name"])
    with pytest.raises(exceptions.RenderException, match="no column"):
        make_filter(grid, "nosuchcolumn,foo")


def test_wrong_column_binding_cannot_silently_clear_results():
    # "name" is a substring of both ImageFileName and FileName: previously
    # the first column won, and a pattern present only in the other column
    # emptied the whole result set without any message
    grid = FakeTreeGrid(["ImageFileName", "FileName", "PID"])
    with pytest.raises(exceptions.RenderException, match="ambiguous"):
        make_filter(grid, "name,svchost")


def test_empty_column_name_matches_every_column():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, ",svchost")
    assert cli_filter._filters[0].column_num is None
    rows = [["4", "system"], ["100", "svchost.exe"]]
    assert kept_rows(cli_filter, rows) == [["100", "svchost.exe"]]


def test_no_column_matches_pattern_against_every_column():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, "svchost")
    rows = [["4", "system"], ["100", "svchost.exe"]]
    assert kept_rows(cli_filter, rows) == [["100", "svchost.exe"]]


#
# Pattern syntax
#


def test_trailing_exclamation_marks_a_regex():
    grid = FakeTreeGrid(["Name"])
    cli_filter = make_filter(grid, "Name,^svchost!")
    assert cli_filter._filters[0].regex
    rows = [["svchost.exe"], ["xsvchost.exe"]]
    assert kept_rows(cli_filter, rows) == [["svchost.exe"]]


def test_invalid_regex_is_rejected_up_front():
    grid = FakeTreeGrid(["Name"])
    with pytest.raises(exceptions.RenderException, match="regular expression"):
        make_filter(grid, "Name,[!")


def test_exclamation_inside_pattern_stays_literal():
    grid = FakeTreeGrid(["Name"])
    cli_filter = make_filter(grid, "Name,foo!bar")
    column_filter = cli_filter._filters[0]
    assert not column_filter.regex
    assert column_filter.pattern == "foo!bar"


def test_pattern_without_exclamation_is_a_literal_substring():
    grid = FakeTreeGrid(["Name"])
    cli_filter = make_filter(grid, "Name,a.c")
    rows = [["a.c"], ["abc"]]
    assert kept_rows(cli_filter, rows) == [["a.c"]]


def test_pattern_may_contain_commas():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, ",foo,bar")
    column_filter = cli_filter._filters[0]
    assert column_filter.column_num is None
    assert column_filter.pattern == "foo,bar"
    cli_filter = make_filter(grid, "Name,foo,bar")
    column_filter = cli_filter._filters[0]
    assert column_filter.column_num == 1
    assert column_filter.pattern == "foo,bar"


@pytest.mark.parametrize(
    "expression",
    [
        "Name,",  # column with no pattern
        ",",  # neither column nor pattern
        "-",  # prefix only
        "+",  # prefix only
        "",  # empty
        "Name,!",  # regex marker with no pattern
        "!",  # regex marker only
    ],
)
def test_empty_pattern_is_an_error_not_a_silent_noop(expression):
    # These used to build no filter at all, silently keeping every row
    grid = FakeTreeGrid(["PID", "Name"])
    with pytest.raises(exceptions.RenderException, match="empty pattern"):
        make_filter(grid, expression)


#
# Include / exclude semantics
#


def test_include_filter_keeps_only_matching_rows():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, "Name,svchost")
    rows = [["4", "system"], ["100", "svchost.exe"], ["104", "svchost.exe"]]
    assert kept_rows(cli_filter, rows) == [["100", "svchost.exe"], ["104", "svchost.exe"]]


def test_plus_prefix_is_an_explicit_include():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, "+Name,svchost")
    rows = [["4", "system"], ["100", "svchost.exe"]]
    assert kept_rows(cli_filter, rows) == [["100", "svchost.exe"]]


def test_exclude_filter_drops_matching_rows():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, "-Name,svchost")
    rows = [["4", "system"], ["100", "svchost.exe"]]
    assert kept_rows(cli_filter, rows) == [["4", "system"]]


def test_filters_combine_as_a_disjunction():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid, "Name,svchost", "Name,system")
    rows = [["4", "system"], ["100", "svchost.exe"], ["200", "csrss.exe"]]
    assert kept_rows(cli_filter, rows) == [["4", "system"], ["100", "svchost.exe"]]


def test_no_filters_keeps_everything():
    grid = FakeTreeGrid(["PID", "Name"])
    cli_filter = make_filter(grid)
    rows = [["4", "system"], ["100", "svchost.exe"]]
    assert kept_rows(cli_filter, rows) == rows
