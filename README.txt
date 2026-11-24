CONFERE ANTES | SUB GLOBAL SOLUTION | FIAP

Objetivo
Ajudar pessoas idosas e demais usuários a interpretar sinais de fraude em
contatos que chegam por ligação ou WhatsApp. A consulta explica a evidência
encontrada e sugere confirmar pelo canal oficial antes de agir.

Windows portátil (64 bits, x64)
Extraia todo o ZIP. Abra a pasta ConfereAntes e dê dois cliques em Iniciar.bat.
No primeiro uso, crie uma senha de 10 a 128 caracteres no terminal.
A digitação da senha fica oculta. O navegador padrão abre automaticamente.
Se necessário, acesse http://127.0.0.1:8765. Mantenha o terminal aberto.

Código-fonte
Requer Python 3.10 ou posterior com sqlite3. Nenhuma biblioteca externa.
No Windows: py app.py --abrir
No Linux ou macOS: python3 app.py --abrir
Saia com Ctrl+C. A base confere.sqlite3 é criada na pasta atual.
Para uma base de demonstração separada, execute com --db demo.sqlite3.
O servidor atende somente no endereço local 127.0.0.1.

Os exemplos clicáveis oferecem relatórios de falso familiar, falsa central
bancária e benefício falso, com canal relatado, cenário e orientação.

Roteiro
1. Abra Analisar mensagem e use o exemplo de benefício. Observe a urgência,
   o pedido de código e o domínio de destino.
2. Em Enviar relato, use (00) 90000-0004 e escolha uma categoria.
3. Consulte o mesmo número. O relato aguarda revisão e fica oculto.
4. Entre no Painel de moderação como moderador e aprove o novo relato.
5. Consulte novamente. Agora a consulta mostra a categoria, a data e a fonte.

Estrutura
app.py contém classes de análise, persistência e servidor HTTP.
indice.py implementa uma árvore B com busca binária dentro de cada página.
desempenho.py reproduz as buscas e inserções com dados sintéticos.
style.css configura a interface. RESULTADOS.txt registra as medições.
Execute python -m pydoc app indice desempenho para consultar as docstrings.

Segurança e privacidade
Senhas são derivadas com PBKDF2-HMAC-SHA256, sal aleatório e comparação
com compare_digest. O painel exige login, sessão temporária e token CSRF.
O servidor local não grava as consultas ou mensagens analisadas. O envio
guarda apenas número fictício, categoria, data e estado de revisão. O aplicativo não abre os endereços
colados nem utiliza bases de WhatsApp, operadoras, Receita ou gov.br.
Os números com DDD 00 representam registros fictícios de demonstração.
A classificação descreve sinais e relatos. Ela não verifica a pessoa por
trás do contato, nem confirma página, mensagem ou identidade institucional.
O escopo desta versão cobre telefones e links. CNPJ e e-mail ficam fora.

Desempenho
Execute python desempenho.py; no portátil, runtime\python.exe desempenho.py.
Os cenários usam 10 mil, 100 mil e 1 milhão de nomes sintéticos, com 2.000
buscas e 2.000 inserções adicionais por cenário. A árvore B usada no login
tem até 31 chaves por página. Com página de tamanho fixo, o custo de busca
e inserção é O(log N). Comparamos visitas médias por caminho a log2(N) e
registramos a duração separadamente. O benchmark mede o índice isolado do
SQLite, do HTTP e da derivação de senha; não simula usuários simultâneos.

Como medir impacto
Em um piloto futuro, medir a proporção de pessoas que identificam o domínio
de destino e escolhem confirmar por um canal oficial em situações simuladas,
assim como o tempo para interpretar o resultado. O protótipo não aferiu
redução de golpes no mundo real.

O runtime opcional Windows é o pacote embarcado do Python 3.13.9:
https://www.python.org/downloads/release/python-3139/
A licença acompanha o runtime.
