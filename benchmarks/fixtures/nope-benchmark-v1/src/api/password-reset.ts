export function createResetToken(req: any) {
  const resetToken = req.body.email + ":" + Date.now();
  return resetToken;
}
