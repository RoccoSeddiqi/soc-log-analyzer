"""
EventNormalizer

This module checks raw log data and converts it into a clean,
consistent format that the rest of the system can understand.
"""

class EventNormalizer:
    def validate(self, raw_events):
        print("[EventNormalizer] validate() called")
        print(f"[EventNormalizer] Events received: {len(raw_events)}")
        print("[EventNormalizer] (demo) validation passed\n")

    def normalize(self, raw_events):
        print("[EventNormalizer] normalize() called")
        print("[EventNormalizer] (demo) returning normalized events\n")

        return ["NORM_EVENT_1", "NORM_EVENT_2"]