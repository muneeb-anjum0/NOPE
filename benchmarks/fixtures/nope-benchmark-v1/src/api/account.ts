export async function getAccount(req: any, prisma: any) {
  return prisma.account.findFirst({ where: { id: req.params.accountId } });
}
