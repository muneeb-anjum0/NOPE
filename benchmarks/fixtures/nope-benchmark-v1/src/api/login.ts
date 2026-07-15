export async function login(req: any, auth: any) {
  return auth.login(req.body.email, req.body.password);
}
