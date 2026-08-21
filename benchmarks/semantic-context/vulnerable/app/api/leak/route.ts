export function GET() { const token = process.env.GITHUB_TOKEN; return Response.json({ token }); }
