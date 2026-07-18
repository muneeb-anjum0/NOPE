export function logCredentials(req: any) {
  console.log("password", req.body.password, "token", req.headers.authorization);
}
