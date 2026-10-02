import { createServer } from "node:http";

const counts = new Map();
createServer((req, res) => {
  const pathname = new URL(req.url, "http://fixture:8000").pathname;
  if (pathname === "/metrics") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(Object.fromEntries(counts)));
    return;
  }
  counts.set(pathname, (counts.get(pathname) ?? 0) + 1);
  if (pathname === "/redirect-allowed") {
    res.writeHead(302, { location: "/ok" }).end();
  } else if (pathname === "/redirect-denied") {
    res.writeHead(302, { location: "/forbidden" }).end();
  } else {
    res.writeHead(200, { "content-type": "text/html" });
    res.end('<a href="/ok">ok</a><a href="/redirect-allowed">redirect</a>');
  }
}).listen(8000, "0.0.0.0", () => console.log("fixture ready"));
