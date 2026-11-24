import { Alert, Button, Form, Input, InputNumber, Select, Space, Switch, Typography, message } from "antd";
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api";
import type { Channel, Monitor } from "../types";

interface FormValues {
  name: string;
  group_name?: string;
  url: string;
  method: "GET" | "HEAD" | "POST";
  header_name?: string;
  header_value?: string;
  body?: string;
  interval_seconds: number;
  timeout_seconds: number;
  expected_status: string;
  assertion_type?: "contains" | "json_eq";
  assertion_value?: string;
  assertion_path?: string;
  failure_threshold: number;
  recovery_threshold: number;
  follow_redirects: boolean;
  enabled: boolean;
  channel_ids: string[];
}

export function MonitorFormPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [form] = Form.useForm<FormValues>();
  const [channels, setChannels] = useState<Channel[]>([]);
  const [error, setError] = useState("");
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState("");

  useEffect(() => {
    void api<{ items: Channel[] }>("/api/v1/notification-channels").then((data) => setChannels(data.items)).catch(() => setChannels([]));
    if (!id) return;
    void api<Monitor>(`/api/v1/monitors/${id}`).then((monitor) => {
      const assertion = monitor.assertions[0];
      form.setFieldsValue({
        name: monitor.name,
        group_name: monitor.group_name || undefined,
        url: monitor.url,
        method: monitor.method,
        interval_seconds: monitor.interval_seconds,
        timeout_seconds: monitor.timeout_seconds,
        expected_status: monitor.expected_status,
        assertion_type: assertion?.type,
        assertion_value: assertion?.value,
        assertion_path: assertion?.path || undefined,
        failure_threshold: monitor.failure_threshold,
        recovery_threshold: monitor.recovery_threshold,
        follow_redirects: monitor.follow_redirects,
        enabled: monitor.enabled,
        channel_ids: monitor.channel_ids,
      });
    });
  }, [form, id]);

  function payload(values: FormValues, includeSecrets: boolean) {
    const headers = values.header_name
      ? [{ name: values.header_name, value: values.header_value || "" }]
      : [];
    const assertions = values.assertion_type && values.assertion_value
      ? [{ type: values.assertion_type, value: values.assertion_value, path: values.assertion_path || null }]
      : [];
    const body: Record<string, unknown> = {
      name: values.name,
      group_name: values.group_name || null,
      url: values.url,
      method: values.method,
      interval_seconds: values.interval_seconds,
      timeout_seconds: values.timeout_seconds,
      expected_status: values.expected_status,
      assertions,
      failure_threshold: values.failure_threshold,
      recovery_threshold: values.recovery_threshold,
      follow_redirects: values.follow_redirects,
      enabled: values.enabled,
      channel_ids: values.channel_ids || [],
    };
    if (!id || includeSecrets || headers.length) body.headers = headers;
    if (values.body !== undefined) body.body = values.body || null;
    return body;
  }

  async function onFinish(values: FormValues) {
    setError("");
    try {
      if (id) {
        await api(`/api/v1/monitors/${id}`, { method: "PATCH", body: JSON.stringify(payload(values, false)) });
        message.success("已保存");
        navigate(`/monitors/${id}`);
      } else {
        const created = await api<Monitor>("/api/v1/monitors", { method: "POST", body: JSON.stringify(payload(values, true)) });
        message.success("已添加");
        navigate(`/monitors/${created.id}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "保存失败");
    }
  }

  async function testConnection() {
    const values = await form.validateFields();
    setTesting(true);
    setTestResult("");
    try {
      const result = await api<{ success: boolean; error_type: string | null; error_message: string | null; http_status: number | null; latency_ms: number | null }>(
        "/api/v1/monitors/test",
        { method: "POST", body: JSON.stringify(payload(values, true)) },
      );
      setTestResult(result.success
        ? `连接成功，状态码 ${result.http_status}，耗时 ${result.latency_ms ?? "--"} ms`
        : `未通过：${result.error_message || result.error_type}`);
    } catch (err) {
      setTestResult(err instanceof Error ? err.message : "测试失败");
    } finally {
      setTesting(false);
    }
  }

  return (
    <>
      <Typography.Title level={3}>{id ? "编辑监控" : "添加监控"}</Typography.Title>
      {error ? <Alert type="error" message={error} style={{ marginBottom: 16 }} /> : null}
      <Form
        form={form}
        layout="vertical"
        style={{ maxWidth: 720 }}
        initialValues={{ method: "GET", interval_seconds: 60, timeout_seconds: 10, expected_status: "200-299", failure_threshold: 3, recovery_threshold: 1, follow_redirects: false, enabled: true, channel_ids: [] }}
        onFinish={onFinish}
      >
        <Form.Item name="name" label="服务名称" rules={[{ required: true, message: "请填写名称" }]}><Input /></Form.Item>
        <Form.Item name="group_name" label="分组"><Input placeholder="可选" /></Form.Item>
        <Form.Item name="url" label="目标 URL" rules={[{ required: true, message: "请填写域名或 URL" }]} extra="只填域名时会补全为 https://"><Input /></Form.Item>
        <Space size="large">
          <Form.Item name="method" label="HTTP 方法"><Select style={{ width: 140 }} options={["GET", "HEAD", "POST"].map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="interval_seconds" label="间隔（秒）"><InputNumber min={30} max={3600} /></Form.Item>
          <Form.Item name="timeout_seconds" label="超时（秒）"><InputNumber min={1} max={30} /></Form.Item>
        </Space>
        <Form.Item name="expected_status" label="预期状态码"><Input placeholder="200-299 或 200,204" /></Form.Item>
        <Typography.Text type="secondary">请求头只在填写时替换。已保存的值不会回显。</Typography.Text>
        <Space>
          <Form.Item name="header_name" label="请求头名称"><Input placeholder="Authorization" /></Form.Item>
          <Form.Item name="header_value" label="请求头值"><Input.Password placeholder="留空则不修改已有请求头" /></Form.Item>
        </Space>
        <Form.Item name="body" label="POST 请求体"><Input.TextArea rows={3} /></Form.Item>
        <Space>
          <Form.Item name="assertion_type" label="断言类型"><Select allowClear style={{ width: 160 }} options={[{ value: "contains", label: "包含文本" }, { value: "json_eq", label: "JSON 字段相等" }]} /></Form.Item>
          <Form.Item name="assertion_path" label="JSON 路径"><Input placeholder="status" /></Form.Item>
          <Form.Item name="assertion_value" label="期望值"><Input /></Form.Item>
        </Space>
        <Space size="large">
          <Form.Item name="failure_threshold" label="故障阈值"><InputNumber min={1} max={20} /></Form.Item>
          <Form.Item name="recovery_threshold" label="恢复阈值"><InputNumber min={1} max={20} /></Form.Item>
          <Form.Item name="follow_redirects" label="跟随重定向" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Space>
        <Form.Item name="channel_ids" label="告警渠道">
          <Select mode="multiple" options={channels.map((item) => ({ value: item.id, label: item.name }))} placeholder="可稍后配置" />
        </Form.Item>
        {testResult ? <Alert type="info" message={testResult} style={{ marginBottom: 16 }} /> : null}
        <Space>
          <Button onClick={() => void testConnection()} loading={testing}>测试连接</Button>
          <Button type="primary" htmlType="submit">保存</Button>
          <Button onClick={() => navigate(-1)}>取消</Button>
        </Space>
      </Form>
    </>
  );
}
