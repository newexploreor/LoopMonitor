import { Alert, Card, Col, Empty, Input, Row, Select, Space, Statistic, Table, Typography } from "antd";
import * as echarts from "echarts";
import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { Sparkline, StatusTag } from "../components/StatusTag";
import type { Dashboard } from "../types";
import { formatAvailability, formatLatency, formatTime } from "../utils/format";

export function DashboardPage() {
  const navigate = useNavigate();
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState<string | undefined>();
  const chartRef = useRef<HTMLDivElement>(null);

  async function load(name = q, current = status) {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ window: "24h" });
      if (name) params.set("q", name);
      if (current) params.set("status", current);
      setData(await api<Dashboard>(`/api/v1/dashboard?${params.toString()}`));
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30000);
    return () => window.clearInterval(timer);
    // eslint is not configured; load on mount and when filters change via buttons.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!chartRef.current || !data) return;
    const chart = echarts.init(chartRef.current);
    chart.setOption({
      tooltip: { trigger: "axis" },
      grid: { left: 48, right: 16, top: 24, bottom: 32 },
      xAxis: { type: "category", data: data.trend.map((item) => item.start.slice(11, 16) || item.start.slice(5, 10)) },
      yAxis: { type: "value", min: 0, max: 100, name: "可用率 %" },
      series: [
        {
          type: "line",
          smooth: true,
          data: data.trend.map((item) => item.availability),
          connectNulls: false,
        },
      ],
    });
    const resize = () => chart.resize();
    window.addEventListener("resize", resize);
    return () => {
      window.removeEventListener("resize", resize);
      chart.dispose();
    };
  }, [data]);

  return (
    <>
      <Typography.Title level={3} className="page-title">监控总览</Typography.Title>
      <Typography.Paragraph type="secondary">
        指标来自最近 24 小时的有效自动检测。没有样本时显示 --，不会把空数据当成 100%。
      </Typography.Paragraph>
      {error ? <Alert type="error" message={error} action={<a onClick={() => void load()}>重试</a>} /> : null}
      <Row gutter={16}>
        <Col span={4}><Card loading={loading}><Statistic title="目标" value={data?.total ?? "--"} /></Card></Col>
        <Col span={4}><Card loading={loading}><Statistic title="正常" value={data?.up ?? "--"} valueStyle={{ color: "#52c41a" }} /></Card></Col>
        <Col span={4}><Card loading={loading}><Statistic title="故障" value={data?.down ?? "--"} valueStyle={{ color: "#ff4d4f" }} /></Card></Col>
        <Col span={4}><Card loading={loading}><Statistic title="暂停" value={data?.paused ?? "--"} /></Card></Col>
        <Col span={4}><Card loading={loading}><Statistic title="未知" value={data?.unknown ?? "--"} /></Card></Col>
        <Col span={4}><Card loading={loading}><Statistic title="未恢复" value={data?.open_incidents ?? "--"} /></Card></Col>
      </Row>
      <Row gutter={16} style={{ marginTop: 16 }}>
        <Col span={6}><Card loading={loading}><Statistic title="24 小时可用率" value={formatAvailability(data?.availability)} /></Card></Col>
        <Col span={6}><Card loading={loading}><Statistic title="平均响应" value={formatLatency(data?.avg_latency_ms)} /></Card></Col>
      </Row>
      <Card title="近期可用率" style={{ marginTop: 16 }} loading={loading}>
        {data && data.trend.every((item) => item.total === 0) ? <Empty description="还没有检测样本" /> : <div ref={chartRef} style={{ height: 260 }} />}
      </Card>
      <Card
        title="服务状态"
        style={{ marginTop: 16 }}
        extra={
          <Space>
            <Input.Search placeholder="名称或地址" allowClear onSearch={(value) => { setQ(value); void load(value, status); }} style={{ width: 220 }} />
            <Select
              allowClear
              placeholder="状态"
              style={{ width: 120 }}
              options={[
                { value: "up", label: "正常" },
                { value: "down", label: "故障" },
                { value: "paused", label: "暂停" },
                { value: "unknown", label: "未知" },
              ]}
              onChange={(value) => { setStatus(value); void load(q, value); }}
            />
          </Space>
        }
      >
        <Table
          rowKey="id"
          loading={loading}
          dataSource={data?.monitors || []}
          locale={{ emptyText: <Empty description="还没有监控目标" /> }}
          pagination={false}
          onRow={(row) => ({ onClick: () => navigate(`/monitors/${row.id}`), style: { cursor: "pointer" } })}
          columns={[
            { title: "名称", dataIndex: "name" },
            { title: "分组", dataIndex: "group_name", render: (value) => value || "--" },
            { title: "地址", dataIndex: "url", ellipsis: true },
            { title: "状态", render: (_, row) => <StatusTag status={row.display_status} stale={row.data_stale} /> },
            { title: "最近检测", render: (_, row) => formatTime(row.last_checked_at) },
            { title: "响应", render: (_, row) => formatLatency(row.last_latency_ms) },
            { title: "24 小时可用率", render: (_, row) => formatAvailability(row.availability) },
            { title: "近期", render: (_, row) => <Sparkline items={row.recent} /> },
          ]}
        />
      </Card>
    </>
  );
}
