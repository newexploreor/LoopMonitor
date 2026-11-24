export function formatAvailability(value: number | null | undefined): string {
  if (value === null || value === undefined) return "--";
  return `${value.toFixed(2)}%`;
}

export function formatLatency(value: number | null | undefined): string {
  if (value === null || value === undefined) return "--";
  return `${Math.round(value)} ms`;
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "--";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "--";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "--";
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes < 60) return `${minutes} 分 ${rest} 秒`;
  const hours = Math.floor(minutes / 60);
  return `${hours} 小时 ${minutes % 60} 分`;
}

export const STATUS_LABEL: Record<string, string> = {
  up: "正常",
  down: "故障",
  paused: "暂停",
  unknown: "未知",
};
