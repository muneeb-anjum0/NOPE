import fs from "fs";

export async function upload(req: any) {
  const file = req.files.avatar;
  fs.writeFileSync("/srv/uploads/" + file.name, file.data);
  return { ok: true };
}
