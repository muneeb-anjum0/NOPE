const http = require("http");

const server = http.createServer((request, response) => {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/redirect") {
    response.writeHead(302, { Location: url.searchParams.get("next") || "https://example.com" });
    response.end();
    return;
  }
  if (url.pathname === "/debug") {
    response.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
    response.end(JSON.stringify({ env: "development", secretPreview: "redacted-in-real-output" }));
    return;
  }
  response.writeHead(200, {
    "Content-Type": "text/html",
    "Set-Cookie": "sid=fixture"
  });
  response.end(`<html><body>hello ${url.searchParams.get("q") || "world"}</body></html>`);
});

server.listen(8080, "0.0.0.0");
