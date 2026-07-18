import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { API_BASE } from "@/lib/api";
import { isE2EFixtureMode } from "@/lib/nope-data";

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
  if (isE2EFixtureMode() && token === "stage8-e2e-session") {
    return { id: "user_stage8", email: "stage8@example.test" };
  }
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
