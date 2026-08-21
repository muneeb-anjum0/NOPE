export async function GET(req) { return Response.json(await db.item.findUnique({ where: { id: req.params.id } })); }
