export function createStore(initial) {
  let value = initial;
  const listeners = new Set();

  function get() {
    return value;
  }

  function set(next) {
    value = typeof next === "function" ? next(value) : next;
    for (const listener of listeners) listener(value);
    return value;
  }

  function update(patch) {
    return set((current) => ({ ...current, ...patch }));
  }

  function subscribe(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  return { get, set, update, subscribe };
}