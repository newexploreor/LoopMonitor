const CSRF_KEY = "lm_csrf";

export function setCsrf(token: string) {
  sessionStorage.setItem(CSRF_KEY, token);
}

function errorMessage(data: unknown): string {
  if (data && typeof data === "object" && "detail" in data) {
    const detail = (data as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) return "提交内容未通过校验";
  }
  return "请求失败";
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");
  const method = (options.method || "GET").toUpperCase();
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (method !== "GET" && method !== "HEAD") {
    const csrf = sessionStorage.getItem(CSRF_KEY);
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const response = await fetch(path, { ...options, headers, credentials: "include" });
  if (response.status === 401 && !path.includes("/auth/login")) {
    window.location.assign("/login");
    throw new Error("未登录");
  }
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(errorMessage(data));
  return data as T;
}
