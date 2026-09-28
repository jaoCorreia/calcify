#!/usr/bin/env node
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { parseArgs } from 'node:util';
import { approve, authorizeApprover, check, createRequest, generateKeys, initialize, protect, revokeApprover, unprotect } from '../src/index.js';

const usage = `Calcify 0.1.3

Uso rapido:
  calcify                              Menu interativo
  calcify check [CHAVE_PUBLICA]        Verifica todos os alvos protegidos
  calcify status [CHAVE_PUBLICA]       Atalho para check
  calcify request [CAMINHO] [MOTIVO]   Pede aprovacao; pergunta o que faltar no terminal
  calcify approve [SOLICITACAO]        Aprova com uma chave privada autorizada

Configuracao e automacao:
  calcify keygen --private-key CAMINHO --public-key CAMINHO
  calcify init --public-key CAMINHO --private-key CAMINHO [--root PROJETO]
  calcify protect CAMINHO... --private-key CAMINHO --reason TEXTO [--root PROJETO]
  calcify unprotect CAMINHO... --private-key CAMINHO --reason TEXTO [--root PROJETO]
  calcify authorize --public-key CAMINHO --label NOME --private-key CHAVE_DO_DONO --reason TEXTO
  calcify revoke ID_DA_CHAVE --private-key CHAVE_DO_DONO --reason TEXTO
  calcify request CAMINHO --reason TEXTO [--trusted-key CHAVE_PUBLICA]
  calcify approve SOLICITACAO --private-key CAMINHO --approver NOME
  calcify check --trusted-key CHAVE_PUBLICA [--root PROJETO]

O comando check sempre verifica o projeto inteiro. Na CI, fixe uma chave publica
fora do projeto com CALCIFY_TRUSTED_KEY ou --trusted-key.
`;

const interactive = Boolean(process.stdin.isTTY && process.stdout.isTTY);
let promptInterface;

function required(value, flag) {
  if (!value) throw new Error(`Informe --${flag}.`);
  return value;
}

function quote(value) {
  return /^[a-zA-Z0-9_./-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`;
}

async function ask(label) {
  if (!interactive) throw new Error(`Entrada interativa indisponivel. Informe ${label} por uma flag.`);
  promptInterface ||= createInterface({ input: process.stdin, output: process.stdout });
  while (true) {
    const answer = (await promptInterface.question(`${label}: `)).trim();
    if (answer) return answer;
    console.log('Este campo nao pode ficar vazio.');
  }
}

async function reasonFor(command, path, given) {
  if (given?.trim()) return given.trim();
  if (interactive) {
    const action = command === 'request' ? 'alterar' : command === 'unprotect' ? 'remover a protecao de' : 'proteger';
    return ask(`Por que ${action} ${path || 'este alvo'}?`);
  }
  const target = path ? ` ${quote(path)}` : '';
  throw new Error(`Falta a justificativa. Use: calcify ${command}${target} --reason "Explique a mudanca".`);
}

async function choose(label, items) {
  if (!items.length) throw new Error('Nenhuma opcao disponivel.');
  if (items.length === 1) {
    console.log(`${label}: ${items[0].label}`);
    return items[0].value;
  }
  console.log(label);
  items.forEach((item, index) => console.log(`  ${index + 1}) ${item.label}`));
  while (true) {
    const index = Number(await ask('Numero')) - 1;
    if (Number.isInteger(index) && index >= 0 && index < items.length) return items[index].value;
    console.log(`Escolha um numero de 1 a ${items.length}.`);
  }
}

function showCheck(root, trustedKey) {
  const result = check(root, trustedKey);
  for (const item of result.approved) console.log(`APROVADO ${item.path} por ${item.approver}: ${item.reason}`);
  for (const item of result.failures) console.error(`BLOQUEADO ${item.path}: conteudo alterado sem aprovacao valida.`);
  console.log(`${result.protected} alvo(s) protegido(s); ${result.approved.length} alteracao(oes) aprovada(s).`);
  if (result.failures.length) {
    console.log('\nPara pedir aprovacao:');
    for (const item of result.failures) console.log(`  calcify request ${quote(item.path)}`);
    console.log('No terminal, o Calcify pergunta a justificativa. Em scripts, use --reason "...".');
    process.exitCode = 1;
  }
  return result;
}

function trustedKeyForCheck(positionals, flag) {
  if (positionals.length > 1) throw new Error('check aceita no maximo uma chave publica. Ele sempre verifica todos os alvos.');
  if (positionals.length && flag) throw new Error('Use a chave publica como argumento ou com --trusted-key, nao os dois.');
  return flag || positionals[0];
}

async function changedTarget(root, trustedKey) {
  const failures = check(root, trustedKey).failures;
  if (!failures.length) throw new Error('Nenhuma alteracao protegida precisa de aprovacao.');
  return choose('Qual alteracao deseja justificar?', failures.map((item) => ({ label: item.path, value: item.path })));
}

async function pendingRequest(root) {
  const dir = join(root, '.calcify', 'requests');
  let files;
  try { files = readdirSync(dir).filter((name) => name.endsWith('.json')).sort(); }
  catch (error) {
    if (error.code === 'ENOENT') throw new Error('Nenhuma solicitacao encontrada em .calcify/requests.');
    throw error;
  }
  const items = files.flatMap((name) => {
    try {
      const request = JSON.parse(readFileSync(join(dir, name), 'utf8'));
      return [{ label: `${request.path || name} — ${request.reason || 'sem motivo'}`, value: join('.calcify', 'requests', name) }];
    } catch { return []; }
  });
  if (!items.length) throw new Error('Nenhuma solicitacao valida encontrada em .calcify/requests.');
  return choose('Qual solicitacao deseja aprovar?', items);
}

async function runRequest(root, path, reason, trustedKey) {
  const target = path || await changedTarget(root, trustedKey);
  const explanation = await reasonFor('request', target, reason);
  const result = createRequest(root, target, explanation, trustedKey);
  console.log(`Solicitacao criada: ${result.path}`);
  console.log(`Motivo: ${result.request.reason}`);
  console.log(`Proximo passo para o aprovador: calcify approve ${quote(relative(root, result.path))} --private-key CAMINHO_DA_CHAVE`);
}

async function runApprove(root, path, privateKey, approver, trustedKey) {
  const request = path || await pendingRequest(root);
  const key = privateKey || (interactive ? await ask('Caminho da chave privada do aprovador (fora do projeto)') : required(privateKey, 'private-key'));
  const name = approver || (interactive ? await ask('Nome de quem aprova') : required(approver, 'approver'));
  const output = approve(root, request, key, name, trustedKey);
  console.log(`Aprovacao assinada: ${output}`);
  showCheck(root, trustedKey);
}

async function runMenu(root) {
  console.log(`Calcify — ${root}\n`);
  const action = await choose('O que deseja fazer?', [
    { label: 'Verificar arquivos protegidos', value: 'check' },
    { label: 'Solicitar aprovacao de uma alteracao', value: 'request' },
    { label: 'Aprovar uma solicitacao', value: 'approve' },
    { label: 'Proteger um arquivo ou diretorio', value: 'protect' },
    { label: 'Ver ajuda', value: 'help' },
    { label: 'Sair', value: 'exit' }
  ]);
  if (action === 'check') showCheck(root);
  if (action === 'request') await runRequest(root);
  if (action === 'approve') await runApprove(root);
  if (action === 'protect') {
    const path = await ask('Arquivo ou diretorio relativo ao projeto');
    const key = await ask('Caminho da chave privada do dono (fora do projeto)');
    const reason = await reasonFor('protect', path);
    const entries = protect(root, [path], key, reason);
    console.log(`Manifesto assinado. ${entries.length} alvo(s) protegido(s).`);
  }
  if (action === 'help') console.log(usage);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command) {
    if (interactive) await runMenu(resolve(process.cwd()));
    else console.log(usage);
    return;
  }
  if (command === 'help' || command === '--help' || command === '-h') {
    console.log(usage);
    return;
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
      label: { type: 'string' },
      help: { type: 'boolean' }
    }
  });
  if (values.help) {
    console.log(usage);
    return;
  }
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
      const reason = await reasonFor('protect', positionals[0], values.reason);
      const entries = protect(root, positionals, privateKey, reason, trustedKey);
      console.log(`Manifesto assinado. ${entries.length} alvo(s) protegido(s).`);
      break;
    }
    case 'unprotect': {
      const reason = await reasonFor('unprotect', positionals[0], values.reason);
      const entries = unprotect(root, positionals, privateKey, reason, trustedKey);
      console.log(`Manifesto assinado. ${entries.length} alvo(s) protegido(s).`);
      break;
    }
    case 'request': {
      if (positionals.length > 2) throw new Error('Use calcify request CAMINHO [MOTIVO] ou --reason TEXTO.');
      if (positionals[1] && values.reason) throw new Error('Informe a justificativa como argumento ou com --reason, nao os dois.');
      await runRequest(root, positionals[0], values.reason || positionals[1], trustedKey);
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
      if (positionals.length > 1) throw new Error('Informe no maximo uma solicitacao.');
      await runApprove(root, positionals[0], privateKey, values.approver, trustedKey);
      break;
    }
    case 'check':
    case 'status': {
      showCheck(root, trustedKeyForCheck(positionals, trustedKey));
      break;
    }
    default: throw new Error(`Comando desconhecido: ${command}. Execute calcify --help para ver as opcoes.`);
  }
}

try {
  await main();
} catch (error) {
  console.error(`Calcify: ${error.message}`);
  process.exitCode = 1;
} finally {
  promptInterface?.close();
}
