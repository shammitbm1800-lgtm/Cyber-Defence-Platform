import time
from collections import deque

from watchdog.events import FileSystemEventHandler


class RansomwareBehaviorMonitor(FileSystemEventHandler):
    def __init__(self, window_seconds=5):
        super().__init__()

        self.window_seconds = window_seconds

        self.created_events = deque()
        self.modified_events = deque()
        self.deleted_events = deque()
        self.moved_events = deque()

    def _cleanup(self, events):
        current_time = time.time()

        while events and current_time - events[0]["time"] > self.window_seconds:
            events.popleft()

    def _record_event(self, events, event_type, path):
        events.append({
            "time": time.time(),
            "event": event_type,
            "path": path
        })

        self._cleanup(events)

    def on_created(self, event):
        if not event.is_directory:
            self._record_event(
                self.created_events,
                "created",
                event.src_path
            )

    def on_modified(self, event):
        if not event.is_directory:
            self._record_event(
                self.modified_events,
                "modified",
                event.src_path
            )

    def on_deleted(self, event):
        if not event.is_directory:
            self._record_event(
                self.deleted_events,
                "deleted",
                event.src_path
            )

    def on_moved(self, event):
        if not event.is_directory:
            self._record_event(
                self.moved_events,
                "moved",
                event.dest_path
            )

    def get_activity_summary(self):
        self._cleanup(self.created_events)
        self._cleanup(self.modified_events)
        self._cleanup(self.deleted_events)
        self._cleanup(self.moved_events)

        return {
            "created": len(self.created_events),
            "modified": len(self.modified_events),
            "deleted": len(self.deleted_events),
            "moved": len(self.moved_events),
            "total_events": (
                len(self.created_events)
                + len(self.modified_events)
                + len(self.deleted_events)
                + len(self.moved_events)
            )
        }