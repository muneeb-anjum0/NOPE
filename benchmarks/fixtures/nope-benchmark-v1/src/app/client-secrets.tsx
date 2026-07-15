export function ClientSecrets() {
  const NEXT_PUBLIC_STRIPE_SECRET = "benchmark_frontend_secret_123456";
  return <span data-secret={NEXT_PUBLIC_STRIPE_SECRET}>ready</span>;
}
