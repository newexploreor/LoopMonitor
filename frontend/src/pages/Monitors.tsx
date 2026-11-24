import { Button, Empty, Input, Popconfirm, Select, Space, Table, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Sparkline, StatusTag } from "../components/StatusTag";
import type { Monitor } from "../types";
import { formatAvailability, formatLatency, formatTime } from "../utils/format";

export function MonitorsPage() {
  const navigate = useNavigate();
  const [items, setItems] = useState<Monitor[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string>();

  async function load(name = q, current = status) {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams();
      if (name) params.set("q", name);
      if (current) params.set("status", current);
      const data = await api<{ items: Monitor[] }>(`/api/v1/monitors?${params.toString()}`);
      setItems(data.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function toggle(row: Monitor) {
    await api(`/api/v1/monitors/${row.id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: !row.enabled }),
    });
    message.success(row.enabled ? "已暂停" : "已恢复，状态重新进入未知");
    await load();
  }

  async function remove(row: Monitor) {
    await api(`/api/v1/monitors/${row.id}`, { method: "DELETE" });
    message.success("已删除");
    await load();
  }

  async function checkNow(row: Monitor) {
    const job = await api<{ job_id: string }>(`/api/v1/monitors/${row.id}/check`, { method: "POST" });
    message.info("已提交立即检测");
    for (let i = 0; i < 20; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      const current = await api<{ status: string; error: string | null }>(`/api/v1/check-jobs/${job.job_id}`);
      if (current.status === "succeeded") {
        message.success("检测完成");
        await load();
        return;
      }
      if (current.status === "failed") {
        message.error(current.error || "检测失败");
        await load();
        return;
      }
    }
  }

  return (
    <>
      <Space style={{ width: "100%", justifyContent: "space-between" }}>
        <Typography.Title level={3} className="page-title">监控管理</Typography.Title>
        <Button type="primary" onClick={() => navigate("/monitors/new")}>添加监控</Button>
      </Space>
      {error ? <Typography.Text type="danger">{error}</Typography.Text> : null}
      <Space style={{ marginBottom: 16 }}>
        <Input.Search placeholder="搜索名称" allowClear onSearch={(value) => { setQ(value); void load(value, status); }} style={{ width: 240 }} />
        <Select
          allowClear
          placeholder="状态"
          style={{ width: 140 }}
          onChange={(value) => { setStatus(value); void load(q, value); }}
          options={["up", "down", "paused", "unknown"].map((value) => ({ value, label: { up: "正常", down: "故障", paused: "暂停", unknown: "未知" }[value] }))}
        />
      </Space>
      <Table
        rowKey="id"
        loading={loading}
        dataSource={items}
        locale={{ emptyText: <Empty description="还没有监控目标" /> }}
        columns={[
          { title: "名称", dataIndex: "name" },
          { title: "分组", dataIndex: "group_name", render: (value) => value || "--" },
          { title: "地址", dataIndex: "url", ellipsis: true },
          { title: "状态", render: (_, row) => <StatusTag status={row.display_status} stale={row.data_stale} /> },
          { title: "最近检测", render: (_, row) => formatTime(row.last_checked_at) },
          { title: "响应", render: (_, row) => formatLatency(row.last_latency_ms) },
          { title: "24 小时可用率", render: (_, row) => formatAvailability(row.availability) },
          { title: "近期", render: (_, row) => <Sparkline items={row.recent} /> },
          {
            title: "操作",
            render: (_, row) => (
              <Space>
                <a onClick={() => navigate(`/monitors/${row.id}`)}>详情</a>
                <a onClick={() => navigate(`/monitors/${row.id}/edit`)}>编辑</a>
                <a onClick={() => void checkNow(row)}>立即检测</a>
                <a onClick={() => void toggle(row)}>{row.enabled ? "暂停" : "启用"}</a>
                <Popconfirm title="确认删除该监控？历史记录会保留。" onConfirm={() => void remove(row)}>
                  <a>删除</a>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
    </>
  );
}
