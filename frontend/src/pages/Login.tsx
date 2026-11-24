import { Alert, Button, Card, Form, Input, Typography } from "antd";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, setCsrf } from "../api";

export function LoginPage() {
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function onFinish(values: { username: string; password: string }) {
    setLoading(true);
    setError("");
    try {
      const result = await api<{ csrf_token: string }>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify(values),
      });
      setCsrf(result.csrf_token);
      navigate("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ minHeight: "100%", display: "grid", placeItems: "center" }}>
      <Card style={{ width: 380 }}>
        <Typography.Title level={3}>登录 LoopMonitor</Typography.Title>
        <Typography.Paragraph type="secondary">单管理员控制台。初始密码由部署时生成，不使用公开默认口令。</Typography.Paragraph>
        {error ? <Alert type="error" message={error} style={{ marginBottom: 16 }} /> : null}
        <Form layout="vertical" onFinish={onFinish}>
          <Form.Item name="username" label="用户名" rules={[{ required: true, message: "请输入用户名" }]}>
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true, message: "请输入密码" }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loading}>
            登录
          </Button>
        </Form>
      </Card>
    </div>
  );
}
