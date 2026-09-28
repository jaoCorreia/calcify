import { createHash, generateKeyPairSync, sign, verify, createPublicKey } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';

const FORMAT = 1;
const CONTROL_DIR = '.calcify';
const MANIFEST = `${CONTROL_DIR}/manifest.json`;
const PROJECT_KEY = `${CONTROL_DIR}/trusted.pub`;
const SHA256 = (data) => createHash('sha256').update(data).digest('hex');
const json = (data) => JSON.stringify(data);

export class CalcifyError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CalcifyError';
  }
}

function fail(message) { throw new CalcifyError(message); }
function file(root, path) { return resolve(root, path); }
function statIfPresent(path) {
  try { return lstatSync(path); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}
function readJson(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { fail(`Nao foi possivel ler ${path}: ${error.message}`); }
}
function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });
}
function overwriteJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}
function keyId(pem) {
  return SHA256(createPublicKey(pem).export({ type: 'spki', format: 'der' }));
}
function publicFromPrivate(privatePem) {
  return createPublicKey(privatePem).export({ type: 'spki', format: 'pem' }).toString();
}
function signature(data, privatePem) {
  return sign(null, Buffer.from(json(data)), privatePem).toString('base64');
}
function validSignature(data, value, publicPem) {
  try { return verify(null, Buffer.from(json(data)), publicPem, Buffer.from(value, 'base64')); }
  catch { return false; }
}

function projectPath(root, input) {
  if (!input || isAbsolute(input)) fail('Use um caminho relativo a raiz do projeto.');
  const absolute = file(root, input);
  const path = relative(root, absolute).split(sep).join('/');
  if (!path || path === '..' || path.startsWith('../')) fail('O caminho deve estar dentro do projeto.');
  if (path === '.git' || path.startsWith('.git/') || path === CONTROL_DIR || path.startsWith(`${CONTROL_DIR}/`)) {
    fail('.git e .calcify nao podem ser calcificados.');
  }
  let cursor = root;
  for (const component of path.split('/')) {
    cursor = resolve(cursor, component);
    if (statIfPresent(cursor)?.isSymbolicLink()) fail(`Link simbolico nao permitido: ${path}`);
  }
  return path;
}

function compareNames(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

function treeFiles(base, prefix = '') {
  const result = [];
  for (const entry of readdirSync(base, { withFileTypes: true }).sort((a, b) => compareNames(a.name, b.name))) {
    const part = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) fail(`Link simbolico nao permitido: ${part}`);
    if (entry.isDirectory()) result.push(...treeFiles(resolve(base, entry.name), part));
    else if (entry.isFile()) result.push([part, SHA256(readFileSync(resolve(base, entry.name)))]);
    else fail(`Tipo de arquivo nao permitido: ${part}`);
  }
  return result;
}

function digestTarget(root, entry) {
  const absolute = file(root, entry.path);
  const stat = statIfPresent(absolute);
  if (!stat) return null;
  if (stat.isSymbolicLink()) fail(`Link simbolico nao permitido: ${entry.path}`);
  if (entry.kind === 'file' && stat.isFile()) return SHA256(readFileSync(absolute));
  if (entry.kind === 'directory' && stat.isDirectory()) return SHA256(json(treeFiles(absolute)));
  fail(`Tipo alterado para ${entry.path}; restaure o tipo original antes de solicitar aprovacao.`);
}

function trustedKey(root, trustedKeyPath) {
  const source = trustedKeyPath || process.env.CALCIFY_TRUSTED_KEY || file(root, PROJECT_KEY);
  try { return readFileSync(source, 'utf8'); }
  catch { fail(`Chave publica indisponivel: ${source}`); }
}

function loadManifest(root, trustedKeyPath) {
  const manifest = readJson(file(root, MANIFEST));
  const publicPem = trustedKey(root, trustedKeyPath);
  if (manifest?.payload?.version !== FORMAT || !Array.isArray(manifest.payload.entries) || !Array.isArray(manifest.payload.approvers)) fail('Formato do manifesto invalido.');
  if (manifest.payload.keyId !== keyId(publicPem)) fail('A chave publica nao corresponde ao manifesto.');
  if (!validSignature(manifest.payload, manifest.signature, publicPem)) fail('Assinatura do manifesto invalida.');
  const paths = new Set();
  for (const entry of manifest.payload.entries) {
    if (!entry || typeof entry.path !== 'string' || !['file', 'directory'].includes(entry.kind) || !/^[a-f0-9]{64}$/.test(entry.sha256)) fail('Entrada invalida no manifesto.');
    if (projectPath(root, entry.path) !== entry.path || paths.has(entry.path)) fail('Caminho duplicado ou invalido no manifesto.');
    paths.add(entry.path);
  }
  const approverIds = new Set([manifest.payload.keyId]);
  for (const approver of manifest.payload.approvers) {
    if (typeof approver.label !== 'string' || !approver.label.trim() || typeof approver.publicKey !== 'string' || approver.keyId !== keyId(approver.publicKey) || approverIds.has(approver.keyId)) fail('Aprovador invalido ou duplicado no manifesto.');
    approverIds.add(approver.keyId);
  }
  return { manifest, publicPem };
}

function privateKey(privateKeyPath, root) {
  if (!privateKeyPath) fail('Informe --private-key com a chave privada mantida fora do projeto.');
  const relativeKey = relative(realpathSync(root), realpathSync(privateKeyPath));
  if (!relativeKey || (!relativeKey.startsWith('..') && !isAbsolute(relativeKey))) fail('A chave privada deve ficar fora do projeto.');
  const privatePem = readFileSync(privateKeyPath, 'utf8');
  return privatePem;
}

function signer(privateKeyPath, publicPem, root) {
  const privatePem = privateKey(privateKeyPath, root);
  if (keyId(publicFromPrivate(privatePem)) !== keyId(publicPem)) fail('A chave privada nao corresponde a chave de confianca.');
  return privatePem;
}

function assertNoOverlap(entries, path) {
  for (const entry of entries) {
    if (entry.path === path) return;
    if (entry.path.startsWith(`${path}/`) || path.startsWith(`${entry.path}/`)) {
      fail(`A protecao de ${path} se sobrepoe a ${entry.path}. Use uma unica entrada.`);
    }
  }
}

export function generateKeys(privateKeyPath, publicKeyPath) {
  if (resolve(privateKeyPath) === resolve(publicKeyPath)) fail('Use caminhos diferentes para chave privada e publica.');
  if (existsSync(privateKeyPath) || existsSync(publicKeyPath)) fail('Os arquivos de chave ja existem.');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' }
  });
  mkdirSync(dirname(privateKeyPath), { recursive: true });
  mkdirSync(dirname(publicKeyPath), { recursive: true });
  writeFileSync(privateKeyPath, privateKey, { mode: 0o600, flag: 'wx' });
  writeFileSync(publicKeyPath, publicKey, { flag: 'wx' });
  return keyId(publicKey);
}

export function initialize(root, publicKeyPath, privateKeyPath) {
  if (existsSync(file(root, MANIFEST)) || existsSync(file(root, PROJECT_KEY))) fail('Calcify ja iniciado neste projeto.');
  const publicPem = readFileSync(publicKeyPath, 'utf8');
  const privatePem = signer(privateKeyPath, publicPem, root);
  const payload = { version: FORMAT, keyId: keyId(publicPem), entries: [], approvers: [], revision: { reason: 'Inicializacao', at: new Date().toISOString() } };
  mkdirSync(file(root, CONTROL_DIR), { recursive: true });
  writeFileSync(file(root, PROJECT_KEY), publicPem, { flag: 'wx' });
  writeJson(file(root, MANIFEST), { payload, signature: signature(payload, privatePem) });
}

export function protect(root, inputs, privateKeyPath, reason, trustedKeyPath) {
  if (!reason?.trim()) fail('Informe --reason para registrar por que o arquivo sera protegido ou atualizado.');
  if (!inputs.length) fail('Informe ao menos um arquivo ou diretorio.');
  const { manifest, publicPem } = loadManifest(root, trustedKeyPath);
  const privatePem = signer(privateKeyPath, publicPem, root);
  const entries = [...manifest.payload.entries];
  for (const input of inputs) {
    const path = projectPath(root, input);
    const absolute = file(root, path);
    if (!existsSync(absolute)) fail(`Caminho nao encontrado: ${path}`);
    const stat = lstatSync(absolute);
    if (stat.isSymbolicLink()) fail(`Link simbolico nao permitido: ${path}`);
    const kind = stat.isDirectory() ? 'directory' : stat.isFile() ? 'file' : null;
    if (!kind) fail(`Tipo de arquivo nao permitido: ${path}`);
    assertNoOverlap(entries, path);
    const sha256 = digestTarget(root, { path, kind });
    const existing = entries.findIndex((entry) => entry.path === path);
    const next = { path, kind, sha256 };
    if (existing < 0) entries.push(next);
    else entries[existing] = next;
  }
  entries.sort((a, b) => compareNames(a.path, b.path));
  const payload = { ...manifest.payload, entries, revision: { reason: reason.trim(), at: new Date().toISOString() } };
  overwriteJson(file(root, MANIFEST), { payload, signature: signature(payload, privatePem) });
  return entries;
}

export function unprotect(root, inputs, privateKeyPath, reason, trustedKeyPath) {
  if (!reason?.trim()) fail('Informe --reason para registrar por que a protecao sera removida.');
  if (!inputs.length) fail('Informe ao menos um arquivo ou diretorio.');
  const { manifest, publicPem } = loadManifest(root, trustedKeyPath);
  const privatePem = signer(privateKeyPath, publicPem, root);
  const paths = inputs.map((input) => projectPath(root, input));
  for (const path of paths) {
    if (!manifest.payload.entries.some((entry) => entry.path === path)) fail(`O caminho ${path} nao consta no manifesto.`);
  }
  const entries = manifest.payload.entries.filter((entry) => !paths.includes(entry.path));
  const payload = { ...manifest.payload, entries, revision: { reason: reason.trim(), at: new Date().toISOString() } };
  overwriteJson(file(root, MANIFEST), { payload, signature: signature(payload, privatePem) });
  return entries;
}

export function authorizeApprover(root, approverPublicKeyPath, label, privateKeyPath, reason, trustedKeyPath) {
  if (!label?.trim() || !reason?.trim()) fail('Informe --label e --reason para autorizar um aprovador.');
  const { manifest, publicPem } = loadManifest(root, trustedKeyPath);
  const ownerPrivatePem = signer(privateKeyPath, publicPem, root);
  const approverPublicPem = readFileSync(approverPublicKeyPath, 'utf8');
  const id = keyId(approverPublicPem);
  if (id === manifest.payload.keyId || manifest.payload.approvers.some((item) => item.keyId === id)) fail('Esta chave ja esta autorizada.');
  const approvers = [...manifest.payload.approvers, { keyId: id, label: label.trim(), publicKey: approverPublicPem }]
    .sort((a, b) => compareNames(a.keyId, b.keyId));
  const payload = { ...manifest.payload, approvers, revision: { reason: reason.trim(), at: new Date().toISOString() } };
  overwriteJson(file(root, MANIFEST), { payload, signature: signature(payload, ownerPrivatePem) });
  return id;
}

export function revokeApprover(root, approverKeyId, privateKeyPath, reason, trustedKeyPath) {
  if (!reason?.trim()) fail('Informe --reason para revogar um aprovador.');
  const { manifest, publicPem } = loadManifest(root, trustedKeyPath);
  const ownerPrivatePem = signer(privateKeyPath, publicPem, root);
  if (!manifest.payload.approvers.some((item) => item.keyId === approverKeyId)) fail('Aprovador nao encontrado.');
  const approvers = manifest.payload.approvers.filter((item) => item.keyId !== approverKeyId);
  const payload = { ...manifest.payload, approvers, revision: { reason: reason.trim(), at: new Date().toISOString() } };
  overwriteJson(file(root, MANIFEST), { payload, signature: signature(payload, ownerPrivatePem) });
}

export function createRequest(root, input, reason, trustedKeyPath) {
  if (!reason?.trim()) fail('Informe --reason com a justificativa da alteracao.');
  const { manifest } = loadManifest(root, trustedKeyPath);
  const path = projectPath(root, input);
  const entry = manifest.payload.entries.find((item) => item.path === path);
  if (!entry) fail(`O caminho ${path} nao consta no manifesto.`);
  const after = digestTarget(root, entry);
  if (after === entry.sha256) fail('O conteudo nao mudou; nenhuma aprovacao e necessaria.');
  const request = {
    version: FORMAT,
    manifestSha256: SHA256(json(manifest.payload)),
    path,
    before: entry.sha256,
    after,
    reason: reason.trim()
  };
  const id = SHA256(json(request)).slice(0, 16);
  const output = file(root, `${CONTROL_DIR}/requests/${id}.json`);
  writeJson(output, request);
  return { path: output, request };
}

export function approve(root, requestPath, privateKeyPath, approver, trustedKeyPath) {
  if (!approver?.trim()) fail('Informe --approver com a identidade de quem aprovou.');
  const { manifest, publicPem } = loadManifest(root, trustedKeyPath);
  const privatePem = privateKey(privateKeyPath, root);
  const signingKeyId = keyId(publicFromPrivate(privatePem));
  if (signingKeyId !== manifest.payload.keyId && !manifest.payload.approvers.some((item) => item.keyId === signingKeyId)) fail('Esta chave nao pode aprovar neste projeto.');
  const request = readJson(resolve(root, requestPath));
  const entry = manifest.payload.entries.find((item) => item.path === request.path);
  if (request.version !== FORMAT || !entry || request.before !== entry.sha256 || request.manifestSha256 !== SHA256(json(manifest.payload)) || typeof request.reason !== 'string' || !request.reason.trim() || !(request.after === null || /^[a-f0-9]{64}$/.test(request.after))) {
    fail('Solicitacao invalida ou desatualizada.');
  }
  if (request.after !== digestTarget(root, entry) || request.after === request.before) fail('O conteudo atual difere da solicitacao.');
  const payload = { request, approver: approver.trim(), approvedAt: new Date().toISOString(), keyId: signingKeyId };
  const approval = { payload, signature: signature(payload, privatePem) };
  const id = SHA256(json(request)).slice(0, 16);
  const output = file(root, `${CONTROL_DIR}/approvals/${id}.json`);
  writeJson(output, approval);
  return output;
}

export function check(root, trustedKeyPath) {
  const { manifest, publicPem } = loadManifest(root, trustedKeyPath);
  const failures = [];
  const approved = [];
  for (const entry of manifest.payload.entries) {
    const actual = digestTarget(root, entry);
    if (actual === entry.sha256) continue;
    const request = {
      version: FORMAT,
      manifestSha256: SHA256(json(manifest.payload)),
      path: entry.path,
      before: entry.sha256,
      after: actual
    };
    const dir = file(root, `${CONTROL_DIR}/approvals`);
    let found = false;
    if (existsSync(dir)) {
      for (const name of readdirSync(dir)) {
        if (!name.endsWith('.json')) continue;
        let approval;
        try { approval = readJson(resolve(dir, name)); } catch { continue; }
        const saved = approval?.payload?.request;
        if (saved?.version !== request.version || saved?.manifestSha256 !== request.manifestSha256 || saved?.path !== request.path || saved?.before !== request.before || saved?.after !== request.after) continue;
        if (typeof saved.reason !== 'string' || !saved.reason.trim() || typeof approval.payload.approver !== 'string' || !approval.payload.approver.trim()) continue;
        const signingPem = approval.payload.keyId === manifest.payload.keyId
          ? publicPem
          : manifest.payload.approvers.find((item) => item.keyId === approval.payload.keyId)?.publicKey;
        if (!signingPem || !validSignature(approval.payload, approval.signature, signingPem)) continue;
        approved.push({ path: entry.path, approver: approval.payload.approver, reason: saved.reason });
        found = true;
        break;
      }
    }
    if (!found) failures.push({ path: entry.path, expected: entry.sha256, actual });
  }
  return { ok: failures.length === 0, failures, approved, protected: manifest.payload.entries.length };
}
