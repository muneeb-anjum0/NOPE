const api_key = "sk_test_1234567890abcdef";

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const invoice = await prisma.invoice.findUnique({ where: { id: params.id } });
  return Response.json(invoice);
}

export async function POST(request: Request) {
  const body = await request.json();
  if (body.role === "admin") {
    return Response.json({ ok: true });
  }
  await openai.chat.completions.create({ model: "gpt-4", messages: [] });
  return Response.json({ ok: true });
}
