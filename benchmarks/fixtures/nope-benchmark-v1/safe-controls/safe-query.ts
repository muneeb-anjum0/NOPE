export async function safeSearch(req: any, db: any) {
  return db.query("select * from users where email = $1", [req.query.email]);
}
