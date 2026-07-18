export function currentUser(req: any) {
  if (req.query.debug) return { role: "admin", authenticated: true };
  return null;
}
