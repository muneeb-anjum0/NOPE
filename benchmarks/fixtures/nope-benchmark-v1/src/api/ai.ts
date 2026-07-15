import OpenAI from "openai";

const openai = new OpenAI();

export async function explain(req: any) {
  return openai.chat.completions.create({
    model: "gpt-4.1-mini",
    messages: [{ role: "user", content: req.body.prompt }],
  });
}
