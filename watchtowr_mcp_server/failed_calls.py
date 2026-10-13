from contextlib import contextmanager

from fastmcp.exceptions import ToolError

from .client import item_error_summary


class PartialAnswer:
    def __init__(self, answer: str):
        self.answer = answer
        self.attempted_parts = 0
        self.incomplete_lines: list[str] = []

    @contextmanager
    def part(self, name: str):
        self.attempted_parts += 1
        try:
            yield
        except ToolError:
            raise
        except Exception as e:
            self.incomplete_lines.append(f"Incomplete: {name} failed: {item_error_summary(e, f'{name} in {self.answer}')}")

    def failure_count(self) -> int:
        return len(self.incomplete_lines)

    def total(self, value: int, failures_before: int) -> str:
        return f"at least {value}" if self.failure_count() > failures_before else str(value)

    def raise_if_every_part_failed(self) -> None:
        if self.incomplete_lines and len(self.incomplete_lines) == self.attempted_parts:
            raise ToolError(
                "\n".join([f"{self.answer} failed: every part of the answer failed.", *self.incomplete_lines])
            )
