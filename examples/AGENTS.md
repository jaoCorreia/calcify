# Arquivos calcificados

Antes de editar uma feature, consulte `.calcify/manifest.json` para identificar os alvos protegidos. Voce pode ler esses arquivos normalmente.

Se uma mudanca protegida for necessaria:

1. Explique ao usuario o motivo e o impacto da mudanca.
2. Prepare a alteracao e mostre o diff para revisao.
3. Execute `calcify request CAMINHO --reason "justificativa concreta"`.
4. Nao assine a propria solicitacao nem acesse uma chave privada de aprovador. Encaminhe a solicitacao para o usuario ou agente calcificador autorizado.
5. Antes de considerar a tarefa concluida, execute `calcify check` e confirme que a aprovacao vale para o conteudo final.

O manifesto, a lista de aprovadores e os arquivos de aprovacao tambem exigem revisao. Nao trate a ausencia de um hook local como permissao para ignorar a verificacao obrigatoria da CI.
