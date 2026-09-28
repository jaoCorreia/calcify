import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { generateKeys, initialize, protect } from '../src/index.js';

const bin = resolve('bin/calcify.js');

function command(root, ...args) {
  return spawnSync(process.execPath, [bin, ...args], { cwd: root, encoding: 'utf8' });
}

test('CLI guia request e aceita chave publica posicional no check', () => {
  const parent = mkdtempSync(join(tmpdir(), 'calcify-cli-'));
  const root = join(parent, 'project');
  const keys = join(parent, 'keys');
  mkdirSync(root);
  mkdirSync(keys);
  const privateKey = join(keys, 'owner.key');
  const publicKey = join(keys, 'owner.pub');
  generateKeys(privateKey, publicKey);
  initialize(root, publicKey, privateKey);
  writeFileSync(join(root, '.env.example'), 'SAFE=true\n');
  protect(root, ['.env.example'], privateKey, 'Configuracao de exemplo', publicKey);
  writeFileSync(join(root, '.env.example'), 'SAFE=false\n');

  const blocked = command(root, 'check', publicKey);
  assert.equal(blocked.status, 1);
  assert.match(blocked.stderr, /BLOQUEADO \.env\.example/);
  assert.match(blocked.stdout, /calcify request \.env\.example/);

  const missingReason = command(root, 'request', '.env.example');
  assert.equal(missingReason.status, 1);
  assert.match(missingReason.stderr, /--reason "Explique a mudanca"/);

  const requested = command(root, 'request', '.env.example', 'Atualizar configuracao de exemplo');
  assert.equal(requested.status, 0, requested.stderr);
  assert.match(requested.stdout, /Solicitacao criada/);
  const requestName = readdirSync(join(root, '.calcify', 'requests'))[0];
  const approved = command(root, 'approve', join('.calcify', 'requests', requestName), '--private-key', privateKey, '--approver', 'Joao');
  assert.equal(approved.status, 0, approved.stderr);
  assert.match(approved.stdout, /APROVADO \.env\.example/);

  const status = command(root, 'status', publicKey);
  assert.equal(status.status, 0, status.stderr);
  assert.match(status.stdout, /1 alteracao\(oes\) aprovada\(s\)/);
});

test('CLI sem terminal mostra ajuda e nao aguarda entrada', () => {
  const root = mkdtempSync(join(tmpdir(), 'calcify-help-'));
  const result = command(root);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Menu interativo/);
});
