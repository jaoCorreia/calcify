#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { approve, authorizeApprover, check, createRequest, generateKeys, initialize, protect, revokeApprover, unprotect } from '../src/index.js';

const usage = `Calcify 0.1.1

Uso:
  calcify keygen --private-key CAMINHO --public-key CAMINHO
  calcify init --public-key CAMINHO --private-key CAMINHO [--root PROJETO]
  calcify protect CAMINHO... --private-key CAMINHO --reason TEXTO [--root PROJETO]
  calcify unprotect CAMINHO... --private-key CAMINHO --reason TEXTO [--root PROJETO]
  calcify authorize --public-key CAMINHO --label NOME --private-key CHAVE_DO_DONO --reason TEXTO
  calcify revoke ID_DA_CHAVE --private-key CHAVE_DO_DONO --reason TEXTO
  calcify request CAMINHO --reason TEXTO [--root PROJETO]
  calcify approve SOLICITACAO --private-key CAMINHO --approver NOME [--root PROJETO]
  calcify check [--trusted-key CAMINHO] [--root PROJETO]

Use CALCIFY_TRUSTED_KEY ou --trusted-key na CI para fixar uma chave publica fora do repositorio.
`;

function required(value, flag) {
  if (!value) throw new Error(`Informe --${flag}.`);
  return value;
}

try {
  const [command, ...args] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help') {
    console.log(usage);
    process.exit(0);
  }
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: {
      root: { type: 'string' },
      'private-key': { type: 'string' },
      'public-key': { type: 'string' },
      'trusted-key': { type: 'string' },
      reason: { type: 'string' },
      approver: { type: 'string' },
      label: { type: 'string' }
    }
  });
  const root = resolve(values.root || process.cwd());
  const privateKey = values['private-key'];
  const trustedKey = values['trusted-key'];
  switch (command) {
    case 'keygen': {
      const id = generateKeys(required(privateKey, 'private-key'), required(values['public-key'], 'public-key'));
      console.log(`Chaves criadas. ID da chave: ${id}`);
      break;
    }
    case 'init': {
      initialize(root, required(values['public-key'], 'public-key'), required(privateKey, 'private-key'));
      console.log(`Calcify iniciado em ${root}.`);
      break;
    }
    case 'protect': {
      const entries = protect(root, positionals, privateKey, values.reason, trustedKey);
      console.log(`Manifesto assinado. ${entries.length} alvo(s) protegido(s).`);
      break;
    }
    case 'unprotect': {
      const entries = unprotect(root, positionals, privateKey, values.reason, trustedKey);
      console.log(`Manifesto assinado. ${entries.length} alvo(s) protegido(s).`);
      break;
    }
    case 'request': {
      if (positionals.length !== 1) throw new Error('Informe exatamente um caminho protegido.');
      const result = createRequest(root, positionals[0], values.reason, trustedKey);
      console.log(`Solicitacao criada: ${result.path}`);
      console.log(`Motivo: ${result.request.reason}`);
      break;
    }
    case 'authorize': {
      const id = authorizeApprover(root, required(values['public-key'], 'public-key'), values.label, privateKey, values.reason, trustedKey);
      console.log(`Aprovador autorizado. ID da chave: ${id}`);
      break;
    }
    case 'revoke': {
      if (positionals.length !== 1) throw new Error('Informe exatamente um ID de chave.');
      revokeApprover(root, positionals[0], privateKey, values.reason, trustedKey);
      console.log(`Aprovador revogado: ${positionals[0]}`);
      break;
    }
    case 'approve': {
      if (positionals.length !== 1) throw new Error('Informe exatamente uma solicitacao.');
      const output = approve(root, positionals[0], privateKey, values.approver, trustedKey);
      console.log(`Aprovacao assinada: ${output}`);
      break;
    }
    case 'check': {
      if (positionals.length) throw new Error('check nao recebe caminhos.');
      const result = check(root, trustedKey);
      for (const item of result.approved) console.log(`APROVADO ${item.path} por ${item.approver}: ${item.reason}`);
      for (const item of result.failures) console.error(`BLOQUEADO ${item.path}: conteudo alterado sem aprovacao valida.`);
      console.log(`${result.protected} alvo(s) protegido(s); ${result.approved.length} alteracao(oes) aprovada(s).`);
      if (!result.ok) process.exitCode = 1;
      break;
    }
    default: throw new Error(`Comando desconhecido: ${command}\n${usage}`);
  }
} catch (error) {
  console.error(`Calcify: ${error.message}`);
  process.exitCode = 1;
}
