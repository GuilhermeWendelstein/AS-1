import { expect, test } from "vitest";
import jwt from "jsonwebtoken";
import { SEGREDO } from "../src/auth.js";
import { api, tokenDe } from "./apoio.js";

test("R1 · a Ana não cancela o ingresso do Bruno", async () => {
  const ana = await tokenDe("ana@exemplo.com");
  const res = await api().delete("/ingressos/2").auth(ana, { type: "bearer" });
  expect(res.status).toBe(403);
});

test("R2 · um CLIENTE recebe 403 nas duas rotas de admin", async () => {
  const cliente = await tokenDe("ana@exemplo.com");
  const vendas = await api().get("/admin/vendas").auth(cliente, { type: "bearer" });
  const show = await api().post("/admin/shows").auth(cliente, { type: "bearer" }).send({
    artista: "Teste", local: "Auditório", data: "2026-12-25", preco: 1000, lugares: 10,
  });
  expect(vendas.status).toBe(403);
  expect(show.status).toBe(403);
});

test("R3 · /me rejeita token ausente, com outro segredo e vencido", async () => {
  const semToken = await api().get("/me");
  const outroSegredo = jwt.sign({ perfil: "CLIENTE" }, "segredo-diferente", { subject: "1" });
  const tokenExpirado = jwt.sign({ perfil: "CLIENTE" }, SEGREDO, { subject: "1", expiresIn: -1 });
  const errado = await api().get("/me").auth(outroSegredo, { type: "bearer" });
  const vencido = await api().get("/me").auth(tokenExpirado, { type: "bearer" });
  expect(semToken.status).toBe(401);
  expect(errado.status).toBe(401);
  expect(vencido.status).toBe(401);
});

test("R5 · GET /me não devolve senha_hash", async () => {
  const token = await tokenDe("ana@exemplo.com");
  const res = await api().get("/me").auth(token, { type: "bearer" });
  expect(res.status).toBe(200);
  expect(res.body).not.toHaveProperty("senha_hash");
});

test("R4 · a compra ignora preco: 1 enviado pelo cliente", async () => {
  const token = await tokenDe("ana@exemplo.com");
  const res = await api().post("/compras").auth(token, { type: "bearer" }).send({ show_id: 2, preco: 1 });
  expect(res.status).toBe(201);
  expect(res.body.preco_pago).toBe(8000);
});

test("R6 · a 6ª senha errada seguida recebe 429", async () => {
  const email = "ana@exemplo.com";
  for (let i = 1; i <= 5; i++) {
    const tentativa = await api().post("/login").send({ email, senha: "errada" });
    expect(tentativa.status).toBe(401);
  }
  const sexta = await api().post("/login").send({ email, senha: "errada" });
  expect(sexta.status).toBe(429);
});

test("R7 · busca com UNION não devolve e-mails de usuários", async () => {
  const payload = "' UNION SELECT 1,email,'x','x',1,1 FROM usuarios -- ";
  const res = await api().get("/shows").query({ busca: payload });
  expect(res.status).toBe(200);
  const resposta = JSON.stringify(res.body);
  expect(resposta).not.toContain("ana@exemplo.com");
  expect(resposta).not.toContain("bruno@exemplo.com");
  expect(resposta).not.toContain("admin@exemplo.com");
});
