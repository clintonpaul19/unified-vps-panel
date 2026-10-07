import test from "node:test";
import assert from "node:assert/strict";

import { list, ApiError } from "../assets/js/api.js";
import { createStore } from "../assets/js/state.js";
import { formatBytes, formatDuration, formatNumber, relativeTime } from "../assets/js/format.js";

test("formatters handle normal and invalid values deterministically", () => {
  assert.equal(formatBytes(1024), "1.00 KB");
  assert.equal(formatBytes(-1), "—");
  assert.equal(formatDuration(3661), "1h 1m");
  assert.equal(formatDuration(-1), "—");
  assert.equal(formatNumber(1234567), new Intl.NumberFormat().format(1234567));
  assert.match(relativeTime(new Date(Date.now() - 5000).toISOString()), /second/);
});

test("store notifies subscribers and supports unsubscribe", () => {
  const store = createStore({ count: 0 });
  const seen = [];
  const unsubscribe = store.subscribe((state) => seen.push(state.count));

  store.update({ count: 1 });
  unsubscribe();
  store.update({ count: 2 });

  assert.deepEqual(seen, [1]);
  assert.equal(store.get().count, 2);
});

test("list parses cursor and supports additional query parameters", async () => {
  const calls = [];
  const previousFetch = globalThis.fetch;

  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return new Response(JSON.stringify([{ id: "one" }]), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "X-Next-Cursor": "next-page",
        "X-Request-ID": "request-123",
      },
    });
  };

  try {
    const result = await list("/v1/servers", {
      limit: 40,
      cursor: "cursor-1",
      params: { include_metrics: "true", empty: "" },
    });

    assert.deepEqual(result.items, [{ id: "one" }]);
    assert.equal(result.nextCursor, "next-page");
    assert.equal(result.requestId, "request-123");
    assert.match(calls[0].url, /limit=40/);
    assert.match(calls[0].url, /cursor=cursor-1/);
    assert.match(calls[0].url, /include_metrics=true/);
    assert.doesNotMatch(calls[0].url, /empty=/);
    assert.equal(calls[0].options.method, "GET");
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("list normalizes HTTP failures as ApiError", async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ detail: "forbidden" }), {
      status: 403,
      headers: { "Content-Type": "application/json", "X-Request-ID": "request-403" },
    });

  try {
    await assert.rejects(
      () => list("/v1/servers"),
      (error) =>
        error instanceof ApiError &&
        error.status === 403 &&
        error.requestId === "request-403" &&
        error.message === "forbidden",
    );
  } finally {
    globalThis.fetch = previousFetch;
  }
});