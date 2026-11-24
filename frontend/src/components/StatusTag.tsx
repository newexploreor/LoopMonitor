import { Tag } from "antd";
import { STATUS_LABEL } from "../utils/format";

const COLOR: Record<string, string> = {
  up: "success",
  down: "error",
  paused: "default",
  unknown: "warning",
};

export function StatusTag({ status, stale }: { status: string; stale?: boolean }) {
  const label = STATUS_LABEL[status] || status;
  return (
    <Tag color={COLOR[status] || "default"}>
      {label}
      {stale ? " · 数据过期" : ""}
    </Tag>
  );
}

export function Sparkline({ items }: { items: { success: boolean; valid: boolean }[] }) {
  if (!items.length) return <span className="spark">--</span>;
  return (
    <span className="spark" title="近期自动检测">
      {items.map((item, index) => (
        <i key={index} className={!item.valid ? "muted" : item.success ? "ok" : "bad"} />
      ))}
    </span>
  );
}
