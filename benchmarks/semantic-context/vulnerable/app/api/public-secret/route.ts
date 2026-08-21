export function GET() { const password = process.env.NEXT_PUBLIC_DATABASE_PASSWORD; return Response.json({ password }); }
