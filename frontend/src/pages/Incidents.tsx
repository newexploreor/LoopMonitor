import { Empty, Select, Table, Typography } from "antd";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { Incident } from "../types";
import { formatDuration, formatTime } from "../utils/format";

export function IncidentsPage() {
  const [items, setItems] = useState<Incident[]>([]);
  const [status, setStatus] = useState<string>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    setLoading(true);
    api<{ items: Incident[] }>(`/api/v1/incidents?${params.toString()}`)
      .then((data) => setItems(data.items))
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, [status]);

  return (
    <>
      <Typography.Title level={3}>异常事件</Typography.Title>
      <Typography.Paragraph type="secondary">连续失败达到阈值后只产生一条未恢复事件，恢复后关闭。单次抖动不会记成故障。</Typography.Paragraph>
      {error ? <Typography.Text type="danger">{error}</Typography.Text> : null}
      <Select
        allowClear
        placeholder="状态"
        style={{ width: 160, marginBottom: 16 }}
        onChange={setStatus}
        options={[{ value: "open", label: "未恢复" }, { value: "recovered", label: "已恢复" }]}
      />
      <Table
        rowKey="id"
        loading={loading}
        dataSource={items}
        locale={{ emptyText: <Empty description="没有异常事件" /> }}
        columns={[
          { title: "服务", render: (_, row) => <Link to={`/monitors/${row.monitor_id}`}>{row.monitor_name || row.monitor_id}</Link> },
          { title: "状态", dataIndex: "status", render: (value) => value === "open" ? "未恢复" : "已恢复" },
          { title: "开始", dataIndex: "started_at", render: formatTime },
          { title: "恢复", dataIndex: "recovered_at", render: formatTime },
          { title: "持续", dataIndex: "duration_seconds", render: formatDuration },
          { title: "错误", dataIndex: "error_type", render: (value) => value || "--" },
          { title: "摘要", dataIndex: "summary" },
        ]}
      />
    </>
  );
}
