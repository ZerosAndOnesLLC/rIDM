/** Calling the orders API with the access token rIDM issued. */
import { config } from "./config";
import { accessToken } from "./session";

export interface Order {
  id: string;
  item: string;
  quantity: number;
  placed_by: string;
  placed_at: string;
}

export interface Who {
  subject: string;
  tenant: string | null;
  client: string | null;
  scopes: string[];
  roles: string[];
  permissions: string[];
  client_only: boolean;
}

export async function whoami(): Promise<Who> {
  return call<Who>("GET", "/whoami");
}

export async function listOrders(): Promise<Order[]> {
  return call<Order[]>("GET", "/orders");
}

export async function placeOrder(item: string, quantity: number): Promise<Order> {
  return call<Order>("POST", "/orders", { item, quantity });
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${config.apiUrl}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${await accessToken()}`,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    // The API answers RFC 6750: 401 `invalid_token`, 403 `insufficient_scope`.
    const problem: unknown = await response.json().catch(() => ({}));
    const { error, error_description } = problem as {
      error?: string;
      error_description?: string;
    };
    throw new Error(
      `${response.status} ${error ?? ""} ${error_description ?? ""}`.trim(),
    );
  }
  return (await response.json()) as T;
}
