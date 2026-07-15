export async function getInvoiceById(req: any, prisma: any) {
  return prisma.invoice.findUnique({ where: { id: req.params.id } });
}
