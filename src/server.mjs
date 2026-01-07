import express from "express";

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = Number(process.env.PORT || 8080);
const ENABLED_VERBS = (process.env.ENABLED_VERBS || "fetch,describe,format,clean,parse,summarize,convert,explain,analyze,classify")
  .split(",").map(s => s.trim()).filter(Boolean);

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "commercial-runtime",
    version: "0.1.0",
    port: PORT,
    enabled_verbs: ENABLED_VERBS
  });
});

// stub endpoints just to prove routing works
for (const v of ENABLED_VERBS) {
  app.post(`/${v}/v1.0.0`, (req, res) => {
    res.json({ ok: true, verb: v, echo: req.body ?? {} });
  });
}

app.listen(PORT, () => {
  console.log(`commercial-runtime listening on :${PORT}`);
});
