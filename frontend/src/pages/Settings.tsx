import { Alert, Button, Card, Descriptions, Form, Input, InputNumber, Space, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { api, setCsrf } from "../api";
import type { SettingsView } from "../types";
import { formatTime } from "../utils/format";

const WORKER_LABEL: Record<string, string> = { ok: "正常", stale: "心跳过期", missing: "未上报" };

export function SettingsPage() {
  const [data, setData] = useState<SettingsView | null>(null);
  const [error, setError] = useState("");

  async function load() {
    try {
      setData(await api<SettingsView>("/api/v1/settings"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function saveRetention(values: { check_retention_days: number; incident_retention_days: number }) {
    setData(await api<SettingsView>("/api/v1/settings", { method: "PATCH", body: JSON.stringify(values) }));
    message.success("保留策略已更新");
  }

  async function changePassword(values: { current_password: string; new_password: string }) {
    const result = await api<{ csrf_token: string }>("/api/v1/auth/password", { method: "POST", body: JSON.stringify(values) });
    setCsrf(result.csrf_token);
    message.success("密码已更新");
  }

  return (
    <>
      <Typography.Title level={3}>系统设置</Typography.Title>
      {error ? <Alert type="error" message={error} /> : null}
      <Card title="运行状态" style={{ marginBottom: 16 }}>
        <Descriptions>
          <Descriptions.Item label="版本">{data?.version || "--"}</Descriptions.Item>
          <Descriptions.Item label="数据库">{data?.database || "--"}</Descriptions.Item>
          <Descriptions.Item label="Worker">{data ? WORKER_LABEL[data.worker] || data.worker : "--"}</Descriptions.Item>
          <Descriptions.Item label="最近心跳">{formatTime(data?.worker_heartbeat)}</Descriptions.Item>
          <Descriptions.Item label="私网探测">{data?.allow_private_targets ? "按白名单允许" : "默认关闭"}</Descriptions.Item>
        </Descriptions>
      </Card>
      <Card title="记录保留" style={{ marginBottom: 16 }}>
        <Form layout="inline" onFinish={saveRetention} initialValues={{ check_retention_days: data?.check_retention_days, incident_retention_days: data?.incident_retention_days }} key={`${data?.check_retention_days}-${data?.incident_retention_days}`}>
          <Form.Item name="check_retention_days" label="检测记录（天）"><InputNumber min={1} max={365} /></Form.Item>
          <Form.Item name="incident_retention_days" label="事件记录（天）"><InputNumber min={1} max={3650} /></Form.Item>
          <Button htmlType="submit" type="primary">保存</Button>
        </Form>
      </Card>
      <Card title="修改密码">
        <Form layout="vertical" style={{ maxWidth: 420 }} onFinish={changePassword}>
          <Form.Item name="current_password" label="当前密码" rules={[{ required: true }]}><Input.Password /></Form.Item>
          <Form.Item name="new_password" label="新密码" rules={[{ required: true, min: 12, message: "至少 12 位" }]}><Input.Password /></Form.Item>
          <Space><Button htmlType="submit">更新密码</Button></Space>
        </Form>
      </Card>
    </>
  );
}
