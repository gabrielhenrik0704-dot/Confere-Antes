# Confere Antes

Protótipo CitizenTech para conferir indícios em telefones e links suspeitos.
Inclui consulta pública, análise de mensagens, envio de relatos fictícios
e painel de moderação. A análise destaca trechos de urgência, pagamento ou
pedido de código e verifica domínios sem abrir os links.

```bash
python app.py --abrir
```

Requer Python 3.10+ com SQLite. Na primeira execução, crie uma senha para
o usuário `moderador`. Acesse http://127.0.0.1:8765 se a aba não abrir.
No pacote Windows portátil, abra `Iniciar.bat`.

Os exemplos clicáveis oferecem relatórios de falso familiar, falsa central
bancária e benefício falso, com canal relatado, cenário e orientação.

Consulte o [guia técnico](README.txt) e os [resultados](RESULTADOS.txt).
