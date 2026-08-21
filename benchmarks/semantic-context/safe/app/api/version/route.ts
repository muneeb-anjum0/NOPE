export function GET() { const version = process.env.BUILD_VERSION; return Response.json({ version }); }
