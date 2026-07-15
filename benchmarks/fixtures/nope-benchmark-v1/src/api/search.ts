export async function unsafeSql(req: any, db: any) {
  const query = "select * from users where email = '" + req.query.email + "'";
  return db.query(query);
}

export async function unsafeNoSql(req: any, collection: any) {
  return collection.findOne({ email: req.body.email, password: req.body.password });
}
