import { Alert, Button, Form, Input, Popconfirm, Space, Switch, Table, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { Channel, Delivery } from "../types";
import { formatTime } from "../utils/format";

export function AlertsPage() {
  const [channels, setChannels] = useState<Channel[]>([]);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [error, setError] = useState("");

  async function load() {
    try {
      const [channelData, deliveryData] = await Promise.all([
        api<{ items: Channel[] }>("/api/v1/notification-channels"),
        api<{ items: Delivery[] }>("/api/v1/notification-deliveries"),
      ]);
      setChannels(channelData.items);
      setDeliveries(deliveryData.items);
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function create(values: { name: string; url: string; secret?: string }) {
    await api("/api/v1/notification-channels", { method: "POST", body: JSON.stringify({ ...values, enabled: true }) });
    message.success("已添加 Webhook");
    await load();
  }

  async function test(row: Channel) {
    const result = await api<{ ok: boolean; error: string | null; status: string }>(`/api/v1/notification-channels/${row.id}/test`, { method: "POST" });
    if (result.ok) message.success("测试通知已送达");
    else message.error(result.error || "测试通知失败");
    await load();
  }

  return (
    <>
      <Typography.Title level={3}>告警管理</Typography.Title>
      <Typography.Paragraph type="secondary">故障和恢复各通知一次。投递失败会按 30 秒、2 分钟、10 分钟重试，接收方用事件 ID 去重。</Typography.Paragraph>
      {error ? <Alert type="error" message={error} /> : null}
      <Form layout="inline" onFinish={create} style={{ margin: "16px 0" }}>
        <Form.Item name="name" rules={[{ required: true, message: "填写名称" }]}><Input placeholder="渠道名称" /></Form.Item>
        <Form.Item name="url" rules={[{ required: true, message: "填写 URL" }]}><Input placeholder="https://example.com/hook" style={{ width: 320 }} /></Form.Item>
        <Form.Item name="secret"><Input.Password placeholder="可选签名密钥" /></Form.Item>
        <Button htmlType="submit" type="primary">添加</Button>
      </Form>
      <Table
        rowKey="id"
        dataSource={channels}
        pagination={false}
        columns={[
          { title: "名称", dataIndex: "name" },
          { title: "地址", dataIndex: "url", ellipsis: true },
          { title: "签名", dataIndex: "has_secret", render: (value) => value ? "已配置" : "无" },
          {
            title: "启用",
            render: (_, row) => (
              <Switch checked={row.enabled} onChange={async (checked) => {
                await api(`/api/v1/notification-channels/${row.id}`, { method: "PATCH", body: JSON.stringify({ enabled: checked }) });
                await load();
              }} />
            ),
          },
          {
            title: "操作",
            render: (_, row) => (
              <Space>
                <a onClick={() => void test(row)}>测试</a>
                <Popconfirm title="删除该渠道？" onConfirm={async () => { await api(`/api/v1/notification-channels/${row.id}`, { method: "DELETE" }); await load(); }}>
                  <a>删除</a>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
      <Typography.Title level={4} style={{ marginTop: 24 }}>通知记录</Typography.Title>
      <Table
        rowKey="id"
        dataSource={deliveries}
        pagination={false}
        columns={[
          { title: "事件", dataIndex: "event_type" },
          { title: "事件 ID", dataIndex: "event_id", ellipsis: true },
          { title: "状态", dataIndex: "status" },
          { title: "尝试", dataIndex: "attempts" },
          { title: "下次重试", dataIndex: "next_retry_at", render: formatTime },
          { title: "错误", dataIndex: "last_error", render: (value) => value || "--" },
          { title: "时间", dataIndex: "created_at", render: formatTime },
        ]}
      />
    </>
  );
}
