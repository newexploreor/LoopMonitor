import { Alert, Card, Col, Descriptions, Empty, Row, Select, Statistic, Table, Typography } from "antd";
import * as echarts from "echarts";
import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../api";
import { StatusTag } from "../components/StatusTag";
import type { CheckItem, Monitor, Statistics } from "../types";
import { formatAvailability, formatDuration, formatLatency, formatTime } from "../utils/format";

export function MonitorDetailPage() {
  const { id } = useParams();
  const [monitor, setMonitor] = useState<Monitor | null>(null);
  const [stats, setStats] = useState<Statistics | null>(null);
  const [checks, setChecks] = useState<CheckItem[]>([]);
  const [windowName, setWindowName] = useState("24h");
  const [error, setError] = useState("");
  const chartRef = useRef<HTMLDivElement>(null);

  async function load(current = windowName) {
    if (!id) return;
    setError("");
    try {
      const [item, statistics, history] = await Promise.all([
        api<Monitor>(`/api/v1/monitors/${id}`),
        api<Statistics>(`/api/v1/monitors/${id}/statistics?window=${current}`),
        api<{ items: CheckItem[] }>(`/api/v1/monitors/${id}/checks?limit=20`),
      ]);
      setMonitor(item);
      setStats(statistics);
      setChecks(history.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    }
  }

  useEffect(() => {
    void load();
  }, [id, windowName]);

  useEffect(() => {
    if (!chartRef.current || !stats) return;
    const chart = echarts.init(chartRef.current);
    chart.setOption({
      tooltip: { trigger: "axis" },
      grid: { left: 48, right: 16, top: 24, bottom: 32 },
      xAxis: { type: "category", data: stats.trend.map((item) => item.start.slice(5, 16)) },
      yAxis: { type: "value", name: "ms" },
      series: [{ type: "line", data: stats.trend.map((item) => item.avg_latency_ms), connectNulls: false }],
    });
    return () => chart.dispose();
  }, [stats]);

  if (error) return <Alert type="error" message={error} />;
  if (!monitor || !stats) return <Card loading />;

  return (
    <>
      <Typography.Title level={3}>{monitor.name}</Typography.Title>
      <Row gutter={16}>
        <Col span={6}><Card><Statistic title="状态" formatter={() => <StatusTag status={monitor.display_status} stale={monitor.data_stale} />} /></Card></Col>
        <Col span={6}><Card><Statistic title="可用率" value={formatAvailability(stats.availability)} /></Card></Col>
        <Col span={6}><Card><Statistic title="平均响应" value={formatLatency(stats.avg_latency_ms)} /></Card></Col>
        <Col span={6}><Card><Statistic title="P95" value={formatLatency(stats.p95_latency_ms)} /></Card></Col>
      </Row>
      <Card style={{ marginTop: 16 }} extra={<Select value={windowName} onChange={setWindowName} options={[{ value: "24h", label: "24 小时" }, { value: "7d", label: "7 天" }, { value: "30d", label: "30 天" }]} />}>
        <Descriptions column={2}>
          <Descriptions.Item label="地址">{monitor.url}</Descriptions.Item>
          <Descriptions.Item label="方法">{monitor.method}</Descriptions.Item>
          <Descriptions.Item label="分组">{monitor.group_name || "--"}</Descriptions.Item>
          <Descriptions.Item label="最近检测">{formatTime(monitor.last_checked_at)}</Descriptions.Item>
          <Descriptions.Item label="连续失败">{monitor.consecutive_failures}</Descriptions.Item>
          <Descriptions.Item label="手动检测（不计入可用率）">{stats.manual_total}</Descriptions.Item>
          <Descriptions.Item label="最近错误">{monitor.last_error_type || "--"}</Descriptions.Item>
          <Descriptions.Item label="有效样本">{stats.success}/{stats.total}</Descriptions.Item>
        </Descriptions>
      </Card>
      <Card title="响应时间" style={{ marginTop: 16 }}>
        {stats.trend.every((item) => item.avg_latency_ms === null) ? <Empty description="该窗口没有成功样本" /> : <div ref={chartRef} style={{ height: 260 }} />}
      </Card>
      <Card title="证书" style={{ marginTop: 16 }}>
        {stats.certificate ? (
          <Descriptions>
            <Descriptions.Item label="状态">{stats.certificate.validation_status}</Descriptions.Item>
            <Descriptions.Item label="到期">{formatTime(stats.certificate.expires_at)}</Descriptions.Item>
            <Descriptions.Item label="剩余天数">{stats.certificate.days_remaining ?? "--"}</Descriptions.Item>
            <Descriptions.Item label="指纹">{stats.certificate.fingerprint || "--"}</Descriptions.Item>
          </Descriptions>
        ) : <Empty description="还没有证书检查记录" />}
      </Card>
      <Card title="关联事件" style={{ marginTop: 16 }}>
        <Table
          rowKey="id"
          dataSource={stats.incidents}
          pagination={false}
          locale={{ emptyText: <Empty description="没有异常事件" /> }}
          columns={[
            { title: "状态", dataIndex: "status", render: (value) => value === "open" ? "未恢复" : "已恢复" },
            { title: "开始", dataIndex: "started_at", render: formatTime },
            { title: "恢复", dataIndex: "recovered_at", render: formatTime },
            { title: "持续", dataIndex: "duration_seconds", render: formatDuration },
            { title: "摘要", dataIndex: "summary" },
          ]}
        />
      </Card>
      <Card title="检测明细" style={{ marginTop: 16 }}>
        <Table
          rowKey="id"
          dataSource={checks}
          pagination={false}
          locale={{ emptyText: <Empty description="还没有检测记录" /> }}
          columns={[
            { title: "时间", dataIndex: "started_at", render: formatTime },
            { title: "来源", dataIndex: "trigger_type", render: (value) => value === "manual" ? "手动" : "自动" },
            { title: "结果", render: (_, row) => row.valid ? (row.success ? "成功" : "失败") : "监控器异常" },
            { title: "状态码", dataIndex: "http_status", render: (value) => value ?? "--" },
            { title: "耗时", dataIndex: "latency_ms", render: (value) => formatLatency(value) },
            { title: "原因", dataIndex: "error_message", render: (value) => value || "--" },
          ]}
        />
      </Card>
    </>
  );
}
