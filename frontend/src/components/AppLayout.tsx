import { Layout, Menu, Typography } from "antd";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";

const ITEMS = [
  { key: "/", label: <Link to="/">监控总览</Link> },
  { key: "/monitors", label: <Link to="/monitors">监控管理</Link> },
  { key: "/incidents", label: <Link to="/incidents">异常事件</Link> },
  { key: "/alerts", label: <Link to="/alerts">告警管理</Link> },
  { key: "/settings", label: <Link to="/settings">系统设置</Link> },
];

export function AppLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const selected = ITEMS.find((item) => item.key !== "/" && location.pathname.startsWith(item.key))?.key || "/";

  async function logout() {
    await api("/api/v1/auth/logout", { method: "POST" });
    sessionStorage.removeItem("lm_csrf");
    navigate("/login");
  }

  return (
    <Layout style={{ minHeight: "100%" }}>
      <Layout.Sider theme="light" width={216}>
        <Typography.Title level={4} style={{ margin: "20px 24px" }}>
          LoopMonitor
        </Typography.Title>
        <Menu mode="inline" selectedKeys={[selected]} items={ITEMS} />
      </Layout.Sider>
      <Layout>
        <Layout.Header style={{ background: "#fff", display: "flex", justifyContent: "flex-end", alignItems: "center" }}>
          <a onClick={logout}>退出</a>
        </Layout.Header>
        <Layout.Content style={{ padding: 24 }}>
          <Outlet />
        </Layout.Content>
      </Layout>
    </Layout>
  );
}
