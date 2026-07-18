import { redirect } from "next/navigation";
import Link from "next/link";
import { getCurrentUser } from "@/lib/auth";

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const user = await getCurrentUser();
  if (user) redirect("/app/projects/local");
  const params = await searchParams;
  return (
    <main className="login-shell">
      <section className="login-panel">
        <Link className="wordmark login-wordmark" href="/">
          NOPE<span className="wordmark-dot">.</span>
        </Link>
        <p className="section-kicker">Local workspace login</p>
        <h1>Open your own fresh dashboard.</h1>
        <p className="muted">
          Credentials are stored in local Postgres. This is intentionally local auth,
          not production identity management.
        </p>
        {params.error ? <p className="login-error">{params.error}</p> : null}
        <form className="app-grid" action="/api/auth/login" method="post">
          <input className="input-shell" name="email" type="email" placeholder="you@example.com" aria-label="Email address" required />
          <input className="input-shell" name="password" type="password" placeholder="At least 8 characters" aria-label="Password" minLength={8} required />
          <button className="button primary" type="submit">
            Continue to dashboard
          </button>
        </form>
      </section>
    </main>
  );
}
