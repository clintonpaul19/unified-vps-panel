from datetime import datetime, timezone

from app.pagination import InvalidCursor, decode_cursor, encode_cursor


def main() -> None:
    secret = "test-secret"
    timestamp = datetime(2026, 10, 7, 10, 0, tzinfo=timezone.utc)
    cursor = encode_cursor(kind="servers", timestamp=timestamp, item_id="00000000-0000-0000-0000-000000000001", secret=secret)
    parsed = decode_cursor(value=cursor, kind="servers", secret=secret)
    assert parsed.timestamp == timestamp
    assert parsed.item_id.endswith("0001")
    try:
        decode_cursor(value=cursor + "x", kind="servers", secret=secret)
    except InvalidCursor:
        pass
    else:
        raise AssertionError("tampered cursor was accepted")
    try:
        decode_cursor(value=cursor, kind="commands", secret=secret)
    except InvalidCursor:
        pass
    else:
        raise AssertionError("cross-endpoint cursor was accepted")
    print("pagination tests passed")


if __name__ == "__main__":
    main()
