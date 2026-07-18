export async function changeEmail(req: any, session: any) {
  const user = session.cookies.user;
  return updateProfile(user.id, { email: req.body.email });
}
