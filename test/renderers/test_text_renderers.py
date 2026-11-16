# Contract tests for the machine-readable CLI renderers (CSV / JSON / JSONL)
#
# These require no memory image, but the conftest --volatility option must
# still be supplied for collection to succeed.

import csv
import datetime
import io
import json

import pytest

from volatility3.cli import text_filter, text_renderer
from volatility3.framework import renderers
from volatility3.framework.renderers import format_hints

WHEN = datetime.datetime(2021, 4, 30, 12, 34, 56, 789012)

COLUMNS = [
    ("Pid", int),
    ("Name", str),
    ("Created", datetime.datetime),
    ("Raw", format_hints.HexBytes),
]

# One row with every kind of absent value, one fully present row
ABSENT_ROW = (
    0,
    (
        renderers.UnreadableValue(),
        renderers.NotApplicableValue(),
        renderers.NotAvailableValue(),
        renderers.UnparsableValue(),
    ),
)
PRESENT_ROW = (0, (4, "system", WHEN, format_hints.HexBytes(b"\x01\x02")))


def build_grid(rows=(ABSENT_ROW, PRESENT_ROW)):
    return renderers.TreeGrid(COLUMNS, iter(rows))


def render(renderer, grid, capsys):
    renderer.render(grid)
    return capsys.readouterr().out


def render_csv(grid, capsys, filters=(), hide_columns=None):
    renderer = text_renderer.CSVRenderer()
    renderer.filter = text_filter.CLIFilter(grid, list(filters))
    renderer.column_hide_list = hide_columns
    out = render(renderer, grid, capsys)
    return list(csv.DictReader(io.StringIO(out)))


def render_json(grid, capsys, renderer_class=text_renderer.JsonRenderer, **kwargs):
    renderer = renderer_class()
    renderer.filter = text_filter.CLIFilter(grid, list(kwargs.get("filters", ())))
    renderer.column_hide_list = kwargs.get("hide_columns")
    out = render(renderer, grid, capsys)
    if renderer_class is text_renderer.JsonLinesRenderer:
        return [json.loads(line) for line in out.strip().splitlines()]
    return json.loads(out)


#
# Missing-data contract: exactly one representation per format
#


def test_csv_absent_values_are_all_empty_fields(capsys):
    rows = render_csv(build_grid(), capsys)
    absent = rows[0]
    for column in ("Pid", "Name", "Created", "Raw"):
        assert absent[column] == ""


def test_csv_output_contains_no_placeholder_strings(capsys):
    rows = render_csv(build_grid(), capsys)
    for row in rows:
        for column in ("Pid", "Name", "Created", "Raw"):
            assert row[column] not in ("N/A", "-")


@pytest.mark.parametrize("renderer_class", [text_renderer.JsonRenderer, text_renderer.JsonLinesRenderer])
def test_json_absent_values_are_all_null(capsys, renderer_class):
    rows = render_json(build_grid(), capsys, renderer_class=renderer_class)
    absent = rows[0]
    for column in ("Pid", "Name", "Created", "Raw"):
        assert absent[column] is None


@pytest.mark.parametrize("renderer_class", [text_renderer.JsonRenderer, text_renderer.JsonLinesRenderer])
def test_json_output_contains_no_placeholder_strings(capsys, renderer_class):
    rows = render_json(build_grid(), capsys, renderer_class=renderer_class)
    for row in rows:
        for column in ("Pid", "Name", "Created", "Raw"):
            assert row[column] not in ("N/A", "-", "")


#
# Date format contract: ISO 8601 in both machine-readable formats
#


def test_csv_datetime_is_iso8601(capsys):
    rows = render_csv(build_grid(), capsys)
    assert rows[1]["Created"] == WHEN.isoformat()


@pytest.mark.parametrize("renderer_class", [text_renderer.JsonRenderer, text_renderer.JsonLinesRenderer])
def test_json_datetime_is_iso8601(capsys, renderer_class):
    rows = render_json(build_grid(), capsys, renderer_class=renderer_class)
    assert rows[1]["Created"] == WHEN.isoformat()


def test_csv_and_json_datetimes_agree(capsys):
    csv_row = render_csv(build_grid(), capsys)[1]
    json_row = render_json(build_grid(), capsys)[1]
    assert csv_row["Created"] == json_row["Created"]
    # ...and the value round-trips through a standard ISO 8601 parser
    assert datetime.datetime.fromisoformat(csv_row["Created"]) == WHEN


#
# Present values still render
#


def test_csv_present_values_render(capsys):
    rows = render_csv(build_grid(), capsys)
    assert rows[1]["Pid"] == "4"
    assert rows[1]["Name"] == "system"
    assert "01 02" in rows[1]["Raw"]


@pytest.mark.parametrize("renderer_class", [text_renderer.JsonRenderer, text_renderer.JsonLinesRenderer])
def test_json_present_values_render(capsys, renderer_class):
    rows = render_json(build_grid(), capsys, renderer_class=renderer_class)
    assert rows[1]["Pid"] == 4
    assert rows[1]["Name"] == "system"
    assert rows[1]["Raw"] == "01 02"


#
# Filters stay aligned with the grid's columns when columns are hidden
#

FILTER_COLUMNS = [("Pid", int), ("PPID", int), ("Name", str)]
FILTER_ROWS = [
    (0, (4, 0, "system")),
    (0, (100, 4, "svchost.exe")),
    (0, (200, 4, "csrss.exe")),
]


def build_filter_grid():
    return renderers.TreeGrid(FILTER_COLUMNS, iter(FILTER_ROWS))


def test_csv_filter_applies_to_hidden_column(capsys):
    # PPID is hidden from the output; a filter on it must still bind to
    # the PPID values, not to whatever column shifted into its place
    grid = build_filter_grid()
    rows = render_csv(grid, capsys, filters=("PPID,4",), hide_columns=["PPID"])
    assert [row["Name"] for row in rows] == ["svchost.exe", "csrss.exe"]
    assert "PPID" not in rows[0]


def test_csv_filter_on_visible_column_with_hidden_column_present(capsys):
    grid = build_filter_grid()
    rows = render_csv(grid, capsys, filters=("Name,svchost",), hide_columns=["PPID"])
    assert [row["Name"] for row in rows] == ["svchost.exe"]


def test_json_filter_applies_to_hidden_column(capsys):
    grid = build_filter_grid()
    rows = render_json(
        grid, capsys, filters=("PPID,4",), hide_columns=["PPID"]
    )
    assert [row["Name"] for row in rows] == ["svchost.exe", "csrss.exe"]
    assert "PPID" not in rows[0]
