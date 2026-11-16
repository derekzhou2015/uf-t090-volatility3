import logging
import re
from typing import Any, List, Optional

from volatility3.framework import constants, exceptions, interfaces

vollog = logging.getLogger(__name__)


class CLIFilter:
    """Parses and applies the row filters given on the command line.

    Filter grammar: ``[+-][columnname,]pattern[!]``

    * A leading ``-`` excludes rows that match, a leading ``+`` (or no
      prefix) keeps only rows that match.
    * The text before the first comma names the column to match against.
      Without a comma the pattern is matched against every column, and an
      empty column name (``,pattern``) does the same, which allows
      patterns that themselves contain commas.  The remainder of the
      filter after the first comma is the pattern, commas included.
    * Column names resolve case-insensitively: an exact match always
      wins, otherwise the name must be a substring of exactly one column
      name.  A name that matches no column, or several columns, raises a
      RenderException instead of silently binding an arbitrary column.
    * A trailing ``!`` marks the pattern as a regular expression, which
      is validated when the filter is constructed.  Without ``!`` the
      pattern is a literal, case-sensitive substring.  A ``!`` anywhere
      else in the pattern is literal.
    * An empty pattern (including one that only held the ``!`` marker)
      is rejected, because it used to silently disable the filter.
    """

    def __init__(self, treegrid, filters: List[str]):
        self._filters = self._prepare(treegrid, filters)

    def _prepare(self, treegrid: interfaces.renderers.TreeGrid, filters: List[str]):
        """Runs through the filter strings and creates the necessary filter objects"""
        output = []

        for filter_string in filters:
            original = filter_string
            exclude = False
            regex = False
            column_name = None
            if filter_string.startswith("-"):
                exclude = True
                filter_string = filter_string[1:]
            elif filter_string.startswith("+"):
                filter_string = filter_string[1:]
            if "," in filter_string:
                column_name, pattern = filter_string.split(",", 1)
                column_name = column_name if column_name else None
            else:
                pattern = filter_string
            if pattern.endswith("!"):
                regex = True
                pattern = pattern[:-1]
            if not pattern:
                raise exceptions.RenderException(
                    f"Filter '{original}' has an empty pattern: "
                    "a filter must match something (use columnname,pattern or pattern)"
                )
            column_num = None
            if column_name is not None:
                column_num = self._resolve_column(treegrid, column_name, original)
            output.append(ColumnFilter(column_num, pattern, regex, exclude, original))

        vollog.log(constants.LOGLEVEL_VVV, "Filters:\n" + repr(output))

        return output

    @staticmethod
    def _resolve_column(
        treegrid: interfaces.renderers.TreeGrid, column_name: str, filter_string: str
    ) -> int:
        """Resolves a column name to a single column index.

        An exact case-insensitive match wins; otherwise the name must be a
        substring of exactly one column name.  Anything else is an error,
        because guessing a column (or falling back to all columns) silently
        changes which rows the filter keeps.
        """
        columns = treegrid.columns
        lowered = column_name.lower()
        for num, column in enumerate(columns):
            if column.name.lower() == lowered:
                return num
        matches = [
            num for num, column in enumerate(columns) if lowered in column.name.lower()
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise exceptions.RenderException(
                f"Filter '{filter_string}' names column '{column_name}' which matches "
                f"no column; available columns: {[column.name for column in columns]}"
            )
        raise exceptions.RenderException(
            f"Filter '{filter_string}' names column '{column_name}' which is ambiguous; "
            f"it matches: {[columns[num].name for num in matches]}"
        )

    def filter(
        self,
        row: List[Any],
    ) -> bool:
        """Filters the row based on each of the column_filters"""
        if not self._filters:
            return False
        found = any(column_filter.found(row) for column_filter in self._filters)
        return not found


class ColumnFilter:
    def __init__(
        self,
        column_num: Optional[int],
        pattern: str,
        regex: bool = False,
        exclude: bool = False,
        original: Optional[str] = None,
    ) -> None:
        self.column_num = column_num
        self.pattern = pattern
        self.regex = regex
        self.exclude = exclude
        self._compiled = None
        if regex:
            try:
                self._compiled = re.compile(pattern)
            except re.error as excp:
                raise exceptions.RenderException(
                    f"Filter '{original if original is not None else pattern}' contains "
                    f"an invalid regular expression '{pattern}': {excp}"
                ) from excp

    def find(self, item) -> bool:
        """Identifies whether an item is found in the appropriate column"""
        try:
            if self._compiled is not None:
                return bool(self._compiled.search(f"{item}"))
            return self.pattern in f"{item}"
        except OSError:
            return False

    def found(self, row: List[Any]) -> bool:
        """Determines whether a row should be filtered

        If the classes exclude value is false, and the necessary pattern is found, the row is not filtered,
        otherwise it is filtered.
        """
        if self.column_num is None:
            found = any(self.find(x) for x in row)
        else:
            found = self.find(row[self.column_num])
        if self.exclude:
            return not found
        return found

    def __repr__(self) -> str:
        """Returns a display of a column filter"""
        return f"ColumnFilter(column={self.column_num},exclude={self.exclude},regex={self.regex},pattern={self.pattern})"
