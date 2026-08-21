import express from "express";

const app = express();

app.get("/api/documents/:id", async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.id } });
  return res.json(document);
});
