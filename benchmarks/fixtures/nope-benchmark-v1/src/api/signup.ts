export async function signup(req: any, users: any) {
  return users.create({ email: req.body.email, password: req.body.password });
}
