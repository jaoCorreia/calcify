import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { approve, authorizeApprover, check, createRequest, generateKeys, initialize, protect, revokeApprover, unprotect } from '../src/index.js';

function fixture() {
  const parent = mkdtempSync(join(tmpdir(), 'calcify-test-'));
  const root = join(parent, 'project');
  const keyDir = join(parent, 'keys');
  mkdirSync(root);
  mkdirSync(keyDir);
  const privateKey = join(keyDir, 'owner.key');
  const publicKey = join(keyDir, 'owner.pub');
  generateKeys(privateKey, publicKey);
  initialize(root, publicKey, privateKey);
  return { root, privateKey, publicKey };
}

test('arquivo alterado exige aprovacao valida para o hash exato', () => {
  const { root, privateKey, publicKey } = fixture();
  const target = join(root, 'auth.js');
  writeFileSync(target, 'export const role = "reader";\n');
  protect(root, ['auth.js'], privateKey, 'Autorizacao critica', publicKey);
  assert.equal(check(root, publicKey).ok, true);
  writeFileSync(target, 'export const role = "admin";\n');
  assert.equal(check(root, publicKey).ok, false);
  const { path } = createRequest(root, 'auth.js', 'Corrigir papel administrativo', publicKey);
  approve(root, path, privateKey, 'Joao', publicKey);
  assert.equal(check(root, publicKey).ok, true);
  assert.equal(check(root, publicKey).approved[0].approver, 'Joao');
  writeFileSync(target, 'export const role = "owner";\n');
  assert.equal(check(root, publicKey).ok, false);
});

test('diretorio detecta criacao e exclusao de arquivos', () => {
  const { root, privateKey, publicKey } = fixture();
  mkdirSync(join(root, 'feature'));
  writeFileSync(join(root, 'feature', 'one.js'), 'one');
  protect(root, ['feature'], privateKey, 'Feature estavel', publicKey);
  writeFileSync(join(root, 'feature', 'two.js'), 'two');
  assert.equal(check(root, publicKey).ok, false);
  const { path } = createRequest(root, 'feature', 'Adicionar modulo', publicKey);
  approve(root, path, privateKey, 'Revisor', publicKey);
  assert.equal(check(root, publicKey).ok, true);
  writeFileSync(join(root, 'feature', 'one.js'), 'changed');
  assert.equal(check(root, publicKey).ok, false);
});

test('manifesto adulterado ou chave substituida falha', () => {
  const { root, privateKey, publicKey } = fixture();
  const otherPrivate = join(root, '..', 'keys', 'other.key');
  const otherPublic = join(root, '..', 'keys', 'other.pub');
  generateKeys(otherPrivate, otherPublic);
  const target = join(root, 'critical.js');
  writeFileSync(target, 'safe');
  protect(root, ['critical.js'], privateKey, 'Critico', publicKey);
  assert.throws(() => check(root, otherPublic), /nao corresponde ao manifesto/);
  const manifestPath = join(root, '.calcify', 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.payload.entries = [];
  writeFileSync(manifestPath, JSON.stringify(manifest));
  assert.throws(() => check(root, publicKey), /Assinatura do manifesto invalida/);
});

test('aprovacao adulterada falha e remocao da protecao requer assinatura', () => {
  const { root, privateKey, publicKey } = fixture();
  const target = join(root, 'critical.js');
  writeFileSync(target, 'safe');
  protect(root, ['critical.js'], privateKey, 'Critico', publicKey);
  writeFileSync(target, 'changed');
  const { path } = createRequest(root, 'critical.js', 'Motivo legitimo', publicKey);
  const approvalPath = approve(root, path, privateKey, 'Revisor', publicKey);
  const approval = JSON.parse(readFileSync(approvalPath, 'utf8'));
  approval.payload.request.reason = 'Motivo alterado';
  writeFileSync(approvalPath, JSON.stringify(approval));
  assert.equal(check(root, publicKey).ok, false);
  unprotect(root, ['critical.js'], privateKey, 'Protecao nao necessaria', publicKey);
  assert.equal(check(root, publicKey).protected, 0);
});

test('protecoes sobrepostas sao rejeitadas', () => {
  const { root, privateKey, publicKey } = fixture();
  mkdirSync(join(root, 'feature'));
  writeFileSync(join(root, 'feature', 'one.js'), 'one');
  protect(root, ['feature'], privateKey, 'Feature', publicKey);
  assert.throws(() => protect(root, ['feature/one.js'], privateKey, 'Duplicado', publicKey), /se sobrepoe/);
});

test('agente autorizado aprova, mas nao pode alterar o manifesto; revogacao invalida sua aprovacao', () => {
  const { root, privateKey, publicKey } = fixture();
  const delegatePrivate = join(root, '..', 'keys', 'delegate.key');
  const delegatePublic = join(root, '..', 'keys', 'delegate.pub');
  generateKeys(delegatePrivate, delegatePublic);
  const target = join(root, 'rules.js');
  writeFileSync(target, 'original');
  protect(root, ['rules.js'], privateKey, 'Regras criticas', publicKey);
  const delegateId = authorizeApprover(root, delegatePublic, 'Agente calcificador', privateKey, 'Delegar revisao', publicKey);
  assert.throws(() => unprotect(root, ['rules.js'], delegatePrivate, 'Tentar remover', publicKey), /nao corresponde/);
  writeFileSync(target, 'revisado');
  const { path } = createRequest(root, 'rules.js', 'Ajustar regra', publicKey);
  approve(root, path, delegatePrivate, 'Agente calcificador', publicKey);
  assert.equal(check(root, publicKey).ok, true);
  revokeApprover(root, delegateId, privateKey, 'Revogar delegacao', publicKey);
  assert.equal(check(root, publicKey).ok, false);
});
