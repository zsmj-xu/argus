"""A shared local execution slot, held by worker and its child processes."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import shutil
from typing import Iterator


@contextmanager
def execution_slot(root: Path) -> Iterator[bool]:
    root.mkdir(parents=True, exist_ok=True)
    with (root.parent / f".{root.name}.execution.lock").open("a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        previous = os.environ.get("ARGUS_EXECUTION_LOCK_FD")
        os.environ["ARGUS_EXECUTION_LOCK_FD"] = str(lock.fileno())
        try:
            # No child can still be using a checkout: it would retain this lock.
            for path in root.iterdir():
                if re.match(r"^[0-9a-f]{32}-", path.name):
                    if path.is_symlink():
                        path.unlink()
                    elif path.is_dir():
                        shutil.rmtree(path)
            yield True
        finally:
            if previous is None:
                os.environ.pop("ARGUS_EXECUTION_LOCK_FD", None)
            else:
                os.environ["ARGUS_EXECUTION_LOCK_FD"] = previous
            # close releases the lock only after inherited child fds close too.


def execution_fds() -> tuple[int, ...]:
    value = os.environ.get("ARGUS_EXECUTION_LOCK_FD")
    if value is None:
        return ()
    return (int(value),)
