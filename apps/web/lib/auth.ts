import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { API_BASE } from "@/lib/api";

export type LocalUser = {
  id: string;
  email: string;
};

export async function getSessionToken() {
  return (await cookies()).get("nope_session")?.value ?? null;
}

export async function getCurrentUser(): Promise<LocalUser | null> {
  const token = await getSessionToken();
  if (!token) return null;
  try {
    const response = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { authorization: `Bearer ${token}` },
      cache: "no-store",
    });
    if (!response.ok) return null;
    const data = (await response.json()) as { user: LocalUser };
    return data.user;
  } catch {
    return null;
  }
}

export async function requireUser(): Promise<LocalUser> {
  const user = await getCurrentUser();
  if (!user) redirect("/login");
  return user;
}
