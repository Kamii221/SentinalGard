"""Shared background worker for monitors.

A monitor's polling/watch loop pushes events onto an in-memory queue;
a separate thread drains it and batches DB writes. This is the pattern
the performance spec asks for across every monitor (queue-based event
processing, batched writes, background worker threads, no busy
polling in the writer -- ``queue.Queue.get(timeout=...)`` blocks until
an item arrives or the flush interval elapses). File/network/
persistence monitors (Phase 7+) reuse this same class.
"""

from __future__ import annotations

import queue
import threading
from typing import Callable, Generic, TypeVar

from agent.logging_setup import get_logger

T = TypeVar("T")

_log = get_logger("monitors.queue_worker")


class QueueWriter(Generic[T]):
    """Drains a queue.Queue[T] on a background thread, batching writes."""

    def __init__(
        self,
        name: str,
        write_batch: Callable[[list[T]], None],
        *,
        batch_size: int = 25,
        flush_interval_seconds: float = 2.0,
    ) -> None:
        self._queue: "queue.Queue[T]" = queue.Queue()
        self._write_batch = write_batch
        self._batch_size = batch_size
        self._flush_interval = flush_interval_seconds
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)

    def put(self, item: T) -> None:
        self._queue.put(item)

    def _drain_batch(self) -> list[T]:
        batch: list[T] = []
        try:
            batch.append(self._queue.get(timeout=self._flush_interval))
        except queue.Empty:
            return batch
        while len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _run(self) -> None:
        while not self._stop_event.is_set():
            batch = self._drain_batch()
            if batch:
                self._flush(batch)

        # Final flush on shutdown so nothing queued gets dropped.
        remaining: list[T] = []
        while True:
            try:
                remaining.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if remaining:
            self._flush(remaining)

    def _flush(self, batch: list[T]) -> None:
        try:
            self._write_batch(batch)
        except Exception:
            _log.exception("Failed to write a batch of %d event(s)", len(batch))
