export async function listTenantInvoices(req: any, prisma: any) {
  return prisma.invoice.findMany({ where: { tenantId: req.body.tenantId } });
}
