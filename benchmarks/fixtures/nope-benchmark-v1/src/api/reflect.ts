export function reflected(req: any) {
  return new Response("<h1>" + req.query.message + "</h1>", {
    headers: { "content-type": "text/html" },
  });
}
