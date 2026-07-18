export async function safeInvoice(req: any, prisma: any, session: any) {
  return prisma.invoice.findFirst({
    where: { id: req.params.id, ownerId: session.user.id },
  });
}
