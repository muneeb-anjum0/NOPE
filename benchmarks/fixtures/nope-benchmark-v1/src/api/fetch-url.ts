export async function fetchPreview(req: any) {
  const target = req.query.url;
  return fetch(target);
}
