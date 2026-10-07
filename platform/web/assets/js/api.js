const DEFAULT_TIMEOUT_MS = 12000;

export class ApiError extends Error {
  constructor(message, { status = 0, requestId = "" } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.requestId = requestId;
  }
}

let unauthorizedHandler = () => {};

export function setUnauthorizedHandler(handler) {
  unauthorizedHandler = typeof handler === "function" ? handler : () => {};
}

async function parseResponse(response) {
  if (response.status === 204) return null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    try {
      return await response.json();
    } catch {
      return {};
    }
  }
  return { detail: (await response.text()).slice(0, 400) };
}

export async function request(path, options = {}) {
  const {
    method = "GET",
    body,
    headers = {},
    signal: externalSignal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  const abortExternal = () => controller.abort();

  if (externalSignal) {
    if (externalSignal.aborted) controller.abort();
    else externalSignal.addEventListener("abort", abortExternal, { once: true });
  }

  const requestHeaders = { Accept: "application/json", ...headers };
  const init = { method, headers: requestHeaders, signal: controller.signal };

  if (body !== undefined) {
    requestHeaders["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }

  try {
    const response = await fetch(path, init);
    const data = await parseResponse(response);
    const requestId = response.headers.get("x-request-id") || "";

    if (response.status === 401 && !path.startsWith("/v1/auth/")) {
      unauthorizedHandler();
    }

    if (!response.ok) {
      const detail =
        typeof data?.detail === "string"
          ? data.detail
          : typeof data?.message === "string"
            ? data.message
            : "The request could not be completed.";
      throw new ApiError(detail, { status: response.status, requestId });
    }

    return data;
  } catch (error) {
    if (error?.name === "AbortError") {
      if (externalSignal?.aborted) throw error;
      throw new ApiError("The request timed out. Please retry.", { status: 408 });
    }
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      navigator.onLine === false
        ? "You appear to be offline."
        : "Network error. Please check the connection and retry.",
      { status: 0 }
    );
  } finally {
    clearTimeout(timeoutId);
    if (externalSignal) externalSignal.removeEventListener("abort", abortExternal);
  }
}

export const api = {
  get: (path, options = {}) => request(path, { ...options, method: "GET" }),
  post: (path, body, options = {}) =>
    request(path, { ...options, method: "POST", body }),
};

export async function list(path, { limit = 50, cursor = "", headers = {}, signal } = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  if (cursor) params.set("cursor", cursor);

  const response = await fetch(path + "?" + params.toString(), {
    method: "GET",
    headers: { Accept: "application/json", ...headers },
    signal,
  });

  const data = await parseResponse(response);
  const requestId = response.headers.get("x-request-id") || "";

  if (response.status === 401) unauthorizedHandler();
  if (!response.ok) {
    const detail = typeof data?.detail === "string" ? data.detail : "The request could not be completed.";
    throw new ApiError(detail, { status: response.status, requestId });
  }

  return {
    items: Array.isArray(data) ? data : [],
    nextCursor: response.headers.get("x-next-cursor") || "",
    requestId,
  };
}