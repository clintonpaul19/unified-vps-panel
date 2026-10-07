const units = ["B", "KB", "MB", "GB", "TB", "PB"];

export function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  let n = bytes;
  let unit = 0;
  while (n >= 1024 && unit < units.length - 1) {
    n /= 1024;
    unit += 1;
  }
  return (n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2)) + " " + units[unit];
}

export function formatNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? new Intl.NumberFormat().format(n) : "—";
}

export function formatDate(value) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Invalid date"
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export function relativeTime(value) {
  if (!value) return "Never";
  const delta = Date.now() - new Date(value).getTime();
  if (!Number.isFinite(delta)) return "Unknown";
  const seconds = Math.round(Math.abs(delta) / 1000);
  const future = delta < 0;

  const table = [
    [60, "second"],
    [3600, "minute"],
    [86400, "hour"],
    [604800, "day"],
    [2592000, "week"],
    [31536000, "month"],
  ];

  let amount = Math.max(1, seconds);
  let unit = "second";
  for (let i = 0; i < table.length; i += 1) {
    const [limit, currentUnit] = table[i];
    if (seconds < limit) {
      amount = Math.max(1, Math.round(seconds / (i === 0 ? 1 : table[i - 1][0])));
      unit = currentUnit;
      break;
    }
    if (i === table.length - 1) {
      amount = Math.max(1, Math.round(seconds / table[i][0]));
      unit = "year";
    }
  }

  const text = amount + " " + unit + (amount === 1 ? "" : "s");
  return future ? "in " + text : text + " ago";
}

export function formatDuration(seconds) {
  const total = Number(seconds);
  if (!Number.isFinite(total) || total < 0) return "—";
  const d = Math.floor(total / 86400);
  const h = Math.floor((total % 86400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  if (d) return d + "d " + h + "h";
  if (h) return h + "h " + m + "m";
  return m + "m";
}

export function statusClass(status) {
  return String(status || "unknown").toLowerCase().replace(/[^a-z0-9_-]/g, "-");
}

export function displayAddress(server) {
  return server.hostname || server.public_ipv4 || server.public_ipv6 || "No address reported";
}

export function metricPercent(server) {
  const metrics = server?.metrics || {};
  const value = Number(metrics.memory_percent ?? metrics.ram_percent);
  return Number.isFinite(value) ? value.toFixed(0) + "%" : "—";
}

export function loadAverage(server) {
  const load = server?.metrics?.loadavg;
  if (!Array.isArray(load) || !load.length) return "—";
  return load.slice(0, 3).map((v) => Number(v).toFixed(2)).join(" / ");
}

export function uptime(server) {
  return formatDuration(server?.metrics?.uptime_seconds);
}