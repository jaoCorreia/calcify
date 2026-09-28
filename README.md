# Calcify

Calcify marca arquivos ou diretorios inteiros como protegidos. O agente pode ler e propor mudancas normalmente, mas uma alteracao protegida so passa na verificacao depois de uma aprovacao assinada para **aquele conteudo exato**. A justificativa fica junto da solicitacao e da aprovacao.

O pacote e uma CLI e uma biblioteca JavaScript sem dependencias externas, para Node.js 20 ou superior. Veja o [site com o jogo](https://calcify-play.jaocorreia.chatgpt.site), o [pacote no npm](https://www.npmjs.com/package/calcify-guard) e o [codigo no GitHub](https://github.com/jaoCorreia/calcify).

## Modelo de uso

1. O dono do projeto cria uma chave Ed25519 e assina o manifesto de protecao.
2. `protect` registra o hash de um arquivo ou de toda a arvore de um diretorio.
3. Ao modificar um alvo protegido, o agente cria uma solicitacao com `request --reason`.
4. O usuario ou um agente calcificador autorizado revisa a diferenca e assina com `approve`.
5. `check` valida o manifesto, o conteudo e a aprovacao. Falha com codigo 1 quando uma mudanca nao esta aprovada.

Uma aprovacao cobre apenas o hash solicitado. Outra edicao, inclusao ou exclusao exige nova aprovacao. O dono pode atualizar o estado de referencia com `protect` ou remover a protecao com `unprotect`, sempre assinando o manifesto e informando o motivo.

## Instalacao

No projeto que sera protegido, instale o pacote pelo npm:

```sh
npm install --save-dev calcify-guard
```

O pacote instala o executavel `calcify`. Depois da instalacao local, use `npx calcify` na raiz do projeto. Para ter o comando direto em qualquer terminal:

```sh
npm install --global calcify-guard
calcify
```

Sem instalacao local ou global, use `npm exec --package calcify-guard -- calcify`. O pacote no registro se chama **`calcify-guard`**; `calcify` e o nome do executavel. Execute `npx calcify` somente depois da instalacao local, para evitar baixar outro pacote com esse nome.

### Fluxo no terminal

`calcify` abre um menu para verificar, solicitar, aprovar e proteger arquivos. Os comandos diretos tambem guiam os campos ausentes quando ha um terminal interativo:

```sh
calcify check ../segredos/owner.pub
calcify request .env.example
calcify approve
calcify status
```

`check` e `status` sempre verificam **todos** os alvos protegidos; o caminho opcional e a chave publica de confianca. `request` pergunta a justificativa. `approve` mostra as solicitacoes e pergunta o caminho da chave privada e o nome do aprovador. Em scripts e na CI, passe os dados explicitamente com `--reason`, `--private-key` e `--approver`.

Tambem e possivel instalar o arquivo `.tgz` disponivel nos releases do GitHub:

```sh
npm install --save-dev /caminho/para/calcify-guard-0.1.3.tgz
```

Os exemplos abaixo rodam **na raiz do projeto protegido**. Mantenha todas as chaves privadas fora do projeto e fora do alcance do agente que edita o codigo. Uma pasta vizinha aparece aqui apenas para ilustrar os caminhos; use um cofre, servico de assinatura ou ambiente separado para a aprovacao real.

```sh
npx calcify keygen --private-key ../segredos/owner.key --public-key ../segredos/owner.pub
npx calcify init --public-key ../segredos/owner.pub --private-key ../segredos/owner.key
npx calcify protect src/auth --private-key ../segredos/owner.key --reason "Fluxo de autorizacao revisado"
npx calcify check --trusted-key ../segredos/owner.pub
```

Versione `.calcify/manifest.json` e `.calcify/trusted.pub`. **Nunca versione as chaves privadas.** Para a verificacao obrigatoria na CI, forneca `--trusted-key` ou `CALCIFY_TRUSTED_KEY` apontando para uma chave publica fixada fora do repositorio.

## Mudanca protegida

Depois de alterar `src/auth`:

```sh
npx calcify check --trusted-key ../segredos/owner.pub
npx calcify request src/auth --reason "Corrigir permissao de leitura" --trusted-key ../segredos/owner.pub
```

O comando devolve o caminho da solicitacao em `.calcify/requests/`. Envie o diff e a solicitacao ao aprovador. Depois de revisar o diff, ele executa:

```sh
npx calcify approve .calcify/requests/ID.json --private-key ../segredos/owner.key --approver "Nome do revisor" --trusted-key ../segredos/owner.pub
npx calcify check --trusted-key ../segredos/owner.pub
```

Versione a solicitacao e a aprovacao em `.calcify/` com a alteracao de codigo. O campo `approver` e uma etiqueta de auditoria; a autorizacao verdadeira vem da chave que assinou.

## Agente calcificador

O dono pode delegar **somente o poder de aprovar** a outra chave. Essa chave nao pode alterar, retirar nem delegar as protecoes.

```sh
npx calcify keygen --private-key ../segredos/calcifier.key --public-key ../segredos/calcifier.pub
npx calcify authorize --public-key ../segredos/calcifier.pub --label "Agente calcificador" --private-key ../segredos/owner.key --reason "Delegar revisao de codigo"
npx calcify approve .calcify/requests/ID.json --private-key ../segredos/calcifier.key --approver "Agente calcificador"
```

Para revogar, passe o ID de chave exibido por `authorize`:

```sh
npx calcify revoke ID_DA_CHAVE --private-key ../segredos/owner.key --reason "Delegacao encerrada"
```

Uma mudanca do manifesto invalida aprovacoes emitidas para a revisao anterior. Nesse caso, gere uma nova solicitacao ou atualize o estado de referencia com a chave do dono.

## Integracao com agentes e CI

Adicione [o exemplo de instrucoes](examples/AGENTS.md) ao `AGENTS.md` do projeto. O arquivo orienta o agente a ler os alvos protegidos, documentar a proposta e pedir revisao quando a verificacao falhar.

O [hook de exemplo](examples/pre-commit) ajuda no desenvolvimento local. A barreira de aceite deve ser um `calcify check` como verificacao **obrigatoria** no servidor de CI, com uma chave publica fixada fora do repositorio e regras de branch que impeçam o agente de ignorar essa verificacao. Execute uma versao confiavel e fixada do pacote nessa CI. Um hook local ou um `AGENTS.md` isolado pode ser contornado por quem controla o processo.

```sh
CALCIFY_TRUSTED_KEY=/caminho/da/ci/owner.pub npx calcify check
```

O Calcify nao muda permissoes do sistema de arquivos: um agente com acesso de escrita ainda consegue alterar o arquivo de trabalho. Ele detecta e bloqueia a **aceitacao** de mudancas nao aprovadas quando a verificacao externa e obrigatoria. Se o agente editor tiver acesso a chave privada do dono ou do aprovador, a separacao de autorizacao deixa de existir.

## API JavaScript

O pacote exporta `generateKeys`, `initialize`, `protect`, `unprotect`, `authorizeApprover`, `revokeApprover`, `createRequest`, `approve` e `check` por `calcify-guard`. A CLI usa essas mesmas funcoes.
