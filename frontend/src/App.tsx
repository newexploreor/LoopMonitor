import { Spin } from "antd";
import { useEffect, useState, type ReactNode } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api, setCsrf } from "./api";
import { AppLayout } from "./components/AppLayout";
import { AlertsPage } from "./pages/Alerts";
import { DashboardPage } from "./pages/Dashboard";
import { IncidentsPage } from "./pages/Incidents";
import { LoginPage } from "./pages/Login";
import { MonitorDetailPage } from "./pages/MonitorDetail";
import { MonitorFormPage } from "./pages/MonitorForm";
import { MonitorsPage } from "./pages/Monitors";
import { SettingsPage } from "./pages/Settings";

function RequireAuth({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    api<{ username: string }>("/api/v1/auth/me")
      .then(() => api<{ csrf_token: string }>("/api/v1/auth/csrf"))
      .then((data) => {
        setCsrf(data.csrf_token);
        setReady(true);
      })
      .catch(() => navigate("/login"));
  }, [navigate]);

  if (!ready) return <Spin style={{ margin: 48 }} />;
  return children;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppLayout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<DashboardPage />} />
        <Route path="/monitors" element={<MonitorsPage />} />
        <Route path="/monitors/new" element={<MonitorFormPage />} />
        <Route path="/monitors/:id" element={<MonitorDetailPage />} />
        <Route path="/monitors/:id/edit" element={<MonitorFormPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
