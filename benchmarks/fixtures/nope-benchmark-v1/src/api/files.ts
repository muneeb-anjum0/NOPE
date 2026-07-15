import fs from "fs";

export function readDownload(req: any) {
  const path = "/srv/uploads/" + req.query.file;
  return fs.readFileSync(path, "utf8");
}
