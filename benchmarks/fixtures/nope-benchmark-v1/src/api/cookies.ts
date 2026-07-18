export function setSessionCookie(res: any, token: string) {
  res.cookie("session", token, { httpOnly: false, secure: false, sameSite: "none" });
}
