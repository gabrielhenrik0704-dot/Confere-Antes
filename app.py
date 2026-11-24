"""Confere Antes: consulta de sinais de fraude e moderação demonstrativa."""

import argparse
from dataclasses import dataclass
from getpass import getpass
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from html import escape
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import re
import secrets
import sqlite3
from time import monotonic
from urllib.parse import parse_qs, urlsplit
import webbrowser

from indice import IndiceUsuarios

CATEGORIAS = ('Pedido de dinheiro em nome de familiar', 'Falso atendimento bancário',
              'Pedido de código do WhatsApp', 'Falsa cobrança de órgão público', 'Outra tentativa')
MENSAGEM_EXEMPLO = ('Seu benefício será bloqueado hoje. Informe o código de verificação '
                    'em https://gov.br.atendimento.example/beneficio.')
REGRAS_MENSAGEM = (
    (r'\b(c[oó]digo de verifica[cç][aã]o|c[oó]digo do whatsapp|informe (?:a|sua) senha)\b',
     'O trecho menciona uma credencial ou código. Confirme o pedido pelo aplicativo oficial.'),
    (r'\b(urgente|agora mesmo|[uú]ltima chance|bloquead[oa] hoje)\b',
     'O trecho cria urgência. Faça uma pausa e confirme com a instituição.'),
    (r'\b(fa[cç]a um pix|pague (?:agora|hoje)|envie dinheiro|taxa de libera[cç][aã]o)\b',
     'O trecho indica um pedido de pagamento. Confirme o destinatário antes de transferir.'),
)
EXEMPLOS = (
    ('(00) 90000-0001', 'Familiar pedindo Pix'),
    ('(00) 90000-0005', 'Falsa central bancária'),
    ('(00) 90000-0006', 'Benefício falso'),
    ('(00) 90000-0002', 'Caso para moderar'),
    ('(00) 90000-0099', 'Sem histórico inicial'),
    ('https://gov.br.atendimento.example/beneficio', 'Link que imita o gov.br'),
)
CASOS = {
    1: ('WhatsApp', 'Uma mensagem dizia ser de um filho que trocou de número e precisava de Pix com urgência.',
        'Ligue para o familiar pelo número que você já tinha antes de transferir.'),
    2: ('Ligação', 'A pessoa se apresentou como funcionária de banco e pediu dados da conta.',
        'Encerre a chamada e contate o banco pelo aplicativo ou pelo número do cartão.'),
    3: ('WhatsApp', 'O contato pediu o código recebido por SMS para supostamente confirmar um cadastro.',
        'Guarde o código de verificação e confira as sessões abertas no aplicativo.'),
    -1: ('Ligação', 'Uma suposta central informou uma compra suspeita e orientou a transferir dinheiro para uma conta segura.',
         'Encerre a chamada e confira a movimentação no aplicativo oficial do banco.'),
    -2: ('SMS', 'O SMS dizia que um benefício seria bloqueado e incluía um endereço fora do gov.br.',
         'Abra o Meu INSS pelo aplicativo oficial e verifique se existe um aviso na sua conta.'),
}
DICAS = 'Confirme pelo aplicativo oficial ou ligue para um número que você já conhece. Nunca informe códigos de verificação.'
CSS = Path(__file__).with_name('style.css')


@dataclass(frozen=True)
class Resultado:
    """Conclusão limitada, evidência observável e orientação."""

    titulo: str
    evidencia: str
    fonte: str
    telefone: str = ''
    historico: tuple = ()
    total: int = 0


class Consultor:
    """Analisa dados localmente e consulta somente relatos aprovados."""

    def __init__(self, banco):
        self.banco = banco

    def consultar(self, entrada):
        """Classifica telefone ou link sem acessar o endereço informado."""
        texto = entrada.strip()
        if re.fullmatch(r'\+?[0-9(). \-]+', texto):
            numero = self.normalizar_telefone(texto)
            total, historico = self.banco.historico_publico(numero)
            telefone = f'({numero[:2]}) {numero[2:-4]}-{numero[-4:]}'
            if total:
                return Resultado('Relato encontrado', 'Há registros aprovados para este número.',
                                 'Base local de demonstração', telefone, historico, total)
            return Resultado('Sem informação suficiente',
                             'Nenhum relato aprovado para esse número na base de demonstração.',
                             'Base local de demonstração', telefone)

        if not texto or any(c.isspace() or c == '\\' or not c.isprintable() for c in texto):
            raise ValueError('Cole um telefone ou link sem espaços internos.')
        if re.fullmatch(r'[^@/]+@[^@/]+', texto):
            raise ValueError('Esta versão consulta telefones e links. Cole o link recebido, caso exista.')
        candidato = texto if '://' in texto else 'https://' + texto
        try:
            url = urlsplit(candidato)
            host = (url.hostname or '').removesuffix('.').encode('idna').decode().lower()
            porta = url.port
        except (ValueError, UnicodeError):
            raise ValueError('O endereço informado está incompleto ou inválido.') from None
        rotulo = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
        if (url.scheme not in ('http', 'https') or len(host) > 253
                or not re.fullmatch(rf'{rotulo}(?:\.{rotulo})+', host)):
            raise ValueError('Informe um link HTTP ou HTTPS com um domínio válido.')
        oficial = host == 'gov.br' or host.endswith('.gov.br')
        fonte = 'Análise local do endereço informado'
        if url.username is not None or url.password is not None:
            return Resultado('Sinal de alerta',
                             f'O endereço tem texto antes de @. O domínio de destino é {host}.', fonte)
        if not oficial and ('gov.br' in host or 'meuinss' in host or 'meu-inss' in host
                             or re.search(r'(gov\.br|meu-?inss)', url.path, re.I)):
            return Resultado('Sinal de alerta',
                             f'O destino é {host}. Ele está fora do domínio gov.br.', fonte)
        if url.scheme == 'http' or porta not in (443, None):
            return Resultado('Sinal de alerta',
                             f'O endereço em {host} usa HTTP ou uma porta fora do padrão HTTPS.', fonte)
        if oficial:
            return Resultado('Domínio sob gov.br',
                             f'O endereço aponta para {host}. A consulta avalia o domínio, sem verificar a página ou a mensagem.',
                             fonte)
        return Resultado('Sem informação suficiente',
                         f'Domínio de destino: {host}. A consulta não encontrou um sinal pelas regras locais.',
                         fonte)


    @staticmethod
    def normalizar_telefone(texto):
        """Normaliza a pontuação e o prefixo brasileiro de um telefone."""
        texto = texto.strip()
        if not re.fullmatch(r'\+?[0-9(). \-]+', texto):
            raise ValueError('Informe um telefone com DDD.')
        numero = re.sub('[^0-9]', '', texto)
        if len(numero) in (12, 13) and numero.startswith('55'):
            numero = numero[2:]
        if len(numero) not in (10, 11):
            raise ValueError('Informe DDD e telefone, com 10 ou 11 dígitos.')
        return numero

    def analisar_mensagem(self, mensagem):
        """Extrai trechos e domínios sem acessar links nem armazenar a mensagem."""
        if not mensagem.strip() or len(mensagem) > 2000:
            raise ValueError('Cole uma mensagem de até 2.000 caracteres.')
        sinais = []
        for padrao, explicacao in REGRAS_MENSAGEM:
            encontro = re.search(padrao, mensagem, re.IGNORECASE)
            if encontro:
                sinais.append((encontro.group(), explicacao))
        enderecos = {}
        for encontro in re.finditer(r'(?<![\w@])(?:https?://|www\.)[^\s<>\x22\x27]+', mensagem, re.I):
            endereco = encontro.group().rstrip('.,;:!?)]}')
            if len(enderecos) >= 8 and endereco not in enderecos:
                break
            if endereco in enderecos:
                continue
            try:
                resultado = self.consultar(endereco)
            except ValueError:
                resultado = Resultado('Endereço inválido', 'Não foi possível ler o domínio.',
                                      'Análise local')
            enderecos[endereco] = resultado
        return sinais, list(enderecos.values())


class Banco:
    """Mantém contas e relatos fictícios em SQLite e indexa nomes na árvore B."""

    def __init__(self, arquivo):
        self.db = sqlite3.connect(arquivo)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS moderadores (
                id INTEGER PRIMARY KEY, usuario TEXT NOT NULL UNIQUE,
                sal BLOB NOT NULL, resumo BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS relatos (
                id INTEGER PRIMARY KEY, numero TEXT NOT NULL,
                categoria TEXT NOT NULL, data TEXT NOT NULL, estado TEXT NOT NULL
                    CHECK (estado IN ('Pendente', 'Aprovado', 'Rejeitado'))
            );
            CREATE INDEX IF NOT EXISTS relato_numero ON relatos(numero, estado, id);
            INSERT OR IGNORE INTO relatos VALUES
                (1, '00900000001', 'Pedido de dinheiro em nome de familiar', '2026-11-20', 'Aprovado'),
                (2, '00900000002', 'Falso atendimento bancário', '2026-11-21', 'Pendente'),
                (3, '00900000003', 'Pedido de código do WhatsApp', '2026-11-22', 'Pendente'),
                (-1, '00900000005', 'Falso atendimento bancário', '2026-11-22', 'Aprovado'),
                (-2, '00900000006', 'Falsa cobrança de órgão público', '2026-11-23', 'Aprovado');
        """)
        self.usuarios = IndiceUsuarios()
        for identificador, usuario in self.db.execute('SELECT id, usuario FROM moderadores ORDER BY id'):
            self.usuarios.inserir(usuario, identificador)

    def iniciar_moderador(self, senha=None):
        """Cria a primeira conta local usando senha fornecida pelo operador."""
        if self.db.execute('SELECT 1 FROM moderadores LIMIT 1').fetchone():
            return
        if senha is None:
            senha = getpass('Crie uma senha para o usuário moderador (10 a 128 caracteres): ')
        if not 10 <= len(senha) <= 128:
            raise ValueError('A senha deve ter de 10 a 128 caracteres.')
        sal = secrets.token_bytes(16)
        with self.db:
            cursor = self.db.execute('INSERT INTO moderadores(usuario, sal, resumo) VALUES (?, ?, ?)',
                                     ('moderador', sal, self.resumo(senha, sal)))
        self.usuarios.inserir('moderador', cursor.lastrowid)

    @staticmethod
    def resumo(senha, sal):
        """Deriva um resumo de senha com PBKDF2-HMAC-SHA256."""
        return pbkdf2_hmac('sha256', senha.encode(), sal, 600_000)

    def autenticar(self, usuario, senha):
        """Verifica credenciais sem revelar se a conta existe."""
        identificador, _ = self.usuarios.buscar(usuario.strip().lower())
        credencial = self.db.execute('SELECT sal, resumo FROM moderadores WHERE id = ?',
                                     (identificador,)).fetchone()
        sal, esperado = credencial or (bytes(16), bytes(32))
        if not 10 <= len(senha) <= 128:
            return False
        confere = compare_digest(self.resumo(senha, sal), esperado)
        return confere and credencial is not None

    def historico_publico(self, numero):
        """Conta relatos aprovados e retorna até dez, em ordem de data."""
        filtro = "FROM relatos WHERE numero = ? AND estado = 'Aprovado'"
        total = self.db.execute(f'SELECT count(*) {filtro}', (numero,)).fetchone()[0]
        recentes = self.db.execute(
            f'SELECT id, categoria, data {filtro} ORDER BY data DESC, id DESC LIMIT 10',
            (numero,)).fetchall()
        return total, tuple(recentes)

    def enviar_relato(self, numero, categoria):
        """Registra um cenário fictício pendente, sem texto livre ou dados pessoais."""
        if not re.fullmatch(r'009[0-9]{8}', numero):
            raise ValueError('Use um número fictício no formato (00) 90000-0004.')
        if categoria not in CATEGORIAS:
            raise ValueError('Escolha uma categoria da lista.')
        with self.db:
            cursor = self.db.execute(
                "INSERT INTO relatos(numero, categoria, data, estado) "
                "SELECT ?, ?, date('now'), 'Pendente' WHERE NOT EXISTS "
                "(SELECT 1 FROM relatos WHERE numero = ? AND categoria = ? AND estado <> 'Rejeitado')",
                (numero, categoria, numero, categoria))
            if cursor.rowcount != 1:
                raise ValueError('Já existe um relato pendente ou aprovado para esse número e categoria.')
            return cursor.lastrowid

    def listar(self):
        """Lista os exemplos do painel de moderação."""
        return self.db.execute('SELECT id, numero, categoria, data, estado FROM relatos ORDER BY id DESC').fetchall()

    def decidir(self, identificador, estado):
        """Decide um relato pendente uma única vez."""
        if estado not in ('Aprovado', 'Rejeitado'):
            raise ValueError('Decisão inválida.')
        with self.db:
            cursor = self.db.execute(
                "UPDATE relatos SET estado = ? WHERE id = ? AND estado = 'Pendente'",
                (estado, identificador))
            return cursor.rowcount == 1


def pagina(titulo, corpo):
    """Monta uma página com navegação e aviso de demonstração."""
    return f"""<!doctype html><html lang="pt-BR"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(titulo)} · Confere Antes</title><link rel="stylesheet" href="/style.css">
<header><nav><a class="brand" href="/"><span>✓</span> Confere Antes</a>
<div class="navegacao"><a href="/mensagem">Analisar mensagem</a>
<a href="/relatar">Enviar relato</a> <a href="/painel">Painel de moderação</a></div></nav></header>
<main>{corpo}</main><footer>Confere Antes · Protótipo acadêmico CitizenTech</footer></html>"""


def perfil_telefone(resultado):
    """Mostra apenas os relatos aprovados e o contexto dos casos preparados."""
    if not resultado.telefone:
        return ''
    itens = []
    for identificador, categoria, data in resultado.historico:
        caso = CASOS.get(identificador)
        fonte = 'Exemplo da base fictícia' if caso else 'Relato de demonstração aprovado pelo moderador'
        detalhes = ''
        if caso:
            canal, cenario, orientacao = caso
            detalhes = (f'<p><strong>Canal relatado</strong> · {escape(canal)}</p>'
                        f'<p>{escape(cenario)}</p><p class="passo">{escape(orientacao)}</p>')
        itens.append(f'<li><h4>{escape(categoria)}</h4>'
                     f'<p class="fonte"><time datetime="{escape(data)}">{escape(data)}</time>'
                     f' · Aprovado · {escape(fonte)}</p>{detalhes}</li>')
    historico = '<ol class="historico">' + ''.join(itens) + '</ol>' if itens else ''
    limite = '<p>Exibindo os dez registros mais recentes.</p>' if resultado.total > 10 else ''
    return (f'<h3>Relatório de {escape(resultado.telefone)}</h3>'
            f'<p><strong>Registros aprovados</strong> · {resultado.total}</p>'
            f'{limite}{historico}<p class="fonte">Os exemplos com DDD 00 são fictícios. '
            'A consulta descreve relatos locais e não identifica o titular da linha.</p>')


def consulta(entrada='', resultado=None, erro=''):
    """Renderiza busca, exemplos e resultado com dados escapados."""
    exemplos = ''.join(
        f'<button class="example" name="entrada" value="{escape(valor)}">{escape(nome)}'
        + (f'<small>{escape(valor)}</small>' if valor.startswith('(') else '')
        + '</button>' for valor, nome in EXEMPLOS
    )
    retorno = ''
    if resultado:
        alerta = ' alerta' if resultado.titulo == 'Sinal de alerta' else ''
        retorno = f"""<section class="resultado{alerta}" aria-labelledby="veredito">
<div class="kicker">Resultado da consulta</div><h2 id="veredito">{escape(resultado.titulo)}</h2>
<p>{escape(resultado.evidencia)}</p>{perfil_telefone(resultado)}<p class="fonte">Fonte: {escape(resultado.fonte)}</p>
<p class="passo">{DICAS}</p></section>"""
    elif erro:
        retorno = f'<p class="erro" role="alert">{escape(erro)}</p>'
    return pagina('Consultar', f"""<div class="intro"><div class="kicker">Consulta de mensagens suspeitas</div>
<h1>Recebeu uma mensagem suspeita?</h1><p>Confira um número de telefone ou um link antes de pagar, clicar ou informar seus dados.</p></div>
<section class="card"><form action="/consulta" method="post"><label for="entrada">Telefone ou link recebido</label>
<div class="busca"><input id="entrada" name="entrada" type="text" maxlength="450" required
value="{escape(entrada)}" placeholder="Ex.: (00) 90000-0001"><button>Consultar</button></div></form>
<form class="exemplos" action="/consulta" method="post"><span>Relatórios e consultas de demonstração</span>{exemplos}</form>
{retorno}</section><aside><strong>Como funciona</strong><p>Use números fictícios na demonstração. A análise de domínio usa regras locais e não abre o link. As consultas e mensagens analisadas não são gravadas.</p></aside>""")


def relato_form(numero='', categoria='', erro='', protocolo=None):
    """Renderiza o formulário de envio e a confirmação com protocolo."""
    opcoes = ''.join(f'<option{" selected" if c == categoria else ""}>{escape(c)}</option>'
                     for c in CATEGORIAS)
    aviso = f'<p class="erro" role="alert">{escape(erro)}</p>' if erro else ''
    if protocolo is not None:
        aviso = (f'<p class="resultado" role="status">Relato #{protocolo} enviado. '
                 'Aguarda revisão do moderador.</p>')
    return pagina('Enviar relato', f"""<div class="intro"><h1>Relatar tentativa de golpe</h1>
<p>Use um número fictício com DDD 00 para demonstrar o envio. O resultado público aparece após a aprovação.</p></div>
<section class="card estreito"><form action="/relatar" method="post">
<label for="numero">Telefone fictício</label><input id="numero" name="numero" type="tel"
maxlength="26" required value="{escape(numero)}" placeholder="(00) 90000-0004">
<label for="categoria">Tipo de tentativa</label><select id="categoria" name="categoria" required>
<option value="">Escolha uma categoria</option>{opcoes}</select>
<button>Enviar para revisão</button></form>{aviso}</section>""")


def mensagem_form(mensagem='', analise=None, erro=''):
    """Renderiza a análise com trechos escapados e sem links clicáveis."""
    retorno = f'<p class="erro" role="alert">{escape(erro)}</p>' if erro else ''
    if analise is not None:
        sinais, links = analise
        itens = [f'<li><strong>“{escape(trecho)}”</strong><p>{escape(explicacao)}</p></li>'
                 for trecho, explicacao in sinais]
        itens.extend(f'<li><strong>{escape(r.titulo)}</strong><p>{escape(r.evidencia)}</p></li>'
                     for r in links)
        evidencias = ('<ul>' + ''.join(itens) + '</ul>' if itens else
                      '<p>As regras locais não encontraram sinais nessa mensagem. Confirme pelo canal oficial.</p>')
        retorno = f'<section class="resultado" aria-label="Resultado"><h2>O que apareceu na análise</h2>{evidencias}<p class="passo">{DICAS}</p></section>'
    return pagina('Analisar mensagem', f"""<div class="intro"><h1>Analisar mensagem suspeita</h1>
<p>O Confere Antes destaca trechos de atenção e examina até oito links sem abri-los.</p></div>
<section class="card"><form action="/mensagem" method="post">
<label for="mensagem">Mensagem recebida</label><textarea id="mensagem" name="mensagem"
maxlength="2000" rows="5" required>{escape(mensagem)}</textarea><button>Analisar mensagem</button></form>
<form class="exemplos" action="/mensagem" method="post"><button class="example" name="mensagem"
value="{escape(MENSAGEM_EXEMPLO)}">Testar exemplo de benefício</button></form>{retorno}</section>""")


def login(erro=''):
    """Renderiza entrada de moderador."""
    aviso = f'<p class="erro" role="alert">{escape(erro)}</p>' if erro else ''
    return pagina('Entrar', f"""<div class="intro"><h1>Painel de moderação</h1>
<p>Entre com a conta configurada ao iniciar o aplicativo.</p></div>
<section class="card estreito"><form action="/entrar" method="post">
<label for="usuario">Usuário</label><input id="usuario" name="usuario" required maxlength="32" autocomplete="username">
<label for="senha">Senha</label><input id="senha" name="senha" type="password" required maxlength="128" autocomplete="current-password">
{aviso}<button>Entrar</button></form></section>""")


def painel(banco, csrf):
    """Apresenta métricas e ações sobre relatos fictícios."""
    relatos = banco.listar()
    estados = ('Pendente', 'Aprovado', 'Rejeitado')
    metricas = ''.join(f'<div class="stat"><strong>{sum(r[4] == e for r in relatos)}</strong><span>{e}</span></div>'
                       for e in estados)
    linhas = []
    for identificador, numero, categoria, data, estado in relatos:
        acoes = ''
        if estado == 'Pendente':
            acoes = f"""<form method="post" action="/decidir" class="acoes">
<input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{identificador}">
<button name="estado" value="Aprovado">Aprovar</button>
<button class="example" name="estado" value="Rejeitado">Rejeitar</button></form>"""
        linhas.append(f'<tr><th scope="row">({numero[:2]}) {numero[2:7]}-{numero[7:]}</th>'
                      f'<td>{escape(categoria)}<small>{data}</small></td><td>{estado}</td><td>{acoes}</td></tr>')
    return pagina('Moderação', f"""<div class="intro"><div class="kicker">Área do moderador</div>
<h1>Relatos em revisão</h1><p>Somente relatos aprovados aparecem na consulta pública.</p></div>
<div class="stats">{metricas}</div><section class="card tabela"><table>
<thead><tr><th>Número fictício</th><th>Motivo</th><th>Situação</th><th>Decisão</th></tr></thead>
<tbody>{''.join(linhas)}</tbody></table></section>
<form method="post" action="/sair"><input type="hidden" name="csrf" value="{csrf}">
<button class="example">Sair da conta</button></form>""")


class Servidor(HTTPServer):
    """Servidor local com uma sessão de moderação por vez."""

    def __init__(self, endereco, banco):
        self.banco = banco
        self.consultor = Consultor(banco)
        self.sessao = None
        self.tentativas = []
        super().__init__(endereco, Rotas)


class Rotas(BaseHTTPRequestHandler):
    """Endpoints HTML e formulários da aplicação local."""

    def log_message(self, formato, *args):
        """Evita gravar entradas de consulta ou caminhos no terminal."""

    def responder(self, corpo, status=200, tipo='text/html; charset=utf-8', extras=()):
        """Envia conteúdo com cabeçalhos restritivos."""
        dados = corpo.encode()
        self.send_response(status)
        self.send_header('Content-Type', tipo)
        self.send_header('Content-Length', str(len(dados)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        for nome, valor in extras:
            self.send_header(nome, valor)
        self.end_headers()
        self.wfile.write(dados)

    def ir(self, destino, cookie=None):
        """Redireciona após submissão de formulário."""
        extras = [('Location', destino)]
        if cookie:
            extras.append(('Set-Cookie', cookie))
        self.responder('', 303, extras=extras)

    def sessao(self):
        """Confere cookie e prazo de validade da sessão local."""
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', '')).get('moderador')
        except CookieError:
            return None
        sessao = self.server.sessao
        if cookie and sessao and monotonic() < sessao[2] and compare_digest(cookie.value.encode(), sessao[0].encode()):
            return sessao
        return None

    def do_GET(self):
        """Serve consulta, painel e estilos."""
        if self.path == '/':
            self.responder(consulta())
        elif self.path == '/style.css':
            self.responder(CSS.read_text(encoding='utf-8'), tipo='text/css; charset=utf-8')
        elif self.path == '/relatar':
            self.responder(relato_form())
        elif self.path == '/mensagem':
            self.responder(mensagem_form())
        elif self.path == '/painel':
            sessao = self.sessao()
            self.responder(painel(self.server.banco, sessao[1]) if sessao else login())
        else:
            self.responder(pagina('Página indisponível', '<h1>Página indisponível</h1>'), 404)

    def do_POST(self):
        """Valida a origem, processa ações públicas e protege ações autenticadas."""
        host = f'127.0.0.1:{self.server.server_port}'
        if self.headers.get('Host') != host or self.headers.get('Origin') != f'http://{host}':
            self.responder('Origem inválida.', 403, tipo='text/plain; charset=utf-8')
            return
        try:
            tamanho = int(self.headers.get('Content-Length', '0'))
            if not 0 < tamanho <= 24576:
                raise ValueError
            dados = parse_qs(self.rfile.read(tamanho).decode(), max_num_fields=6)
        except ValueError:
            self.responder('Formulário inválido.', 400, tipo='text/plain; charset=utf-8')
            return

        def campo(nome):
            return dados.get(nome, [''])[0]

        if self.path == '/consulta':
            entrada = campo('entrada')[:450]
            try:
                self.responder(consulta(entrada, self.server.consultor.consultar(entrada)))
            except ValueError as erro:
                self.responder(consulta(entrada, erro=str(erro)), 400)
        elif self.path == '/relatar':
            numero, categoria = campo('numero')[:26], campo('categoria')
            try:
                protocolo = self.server.banco.enviar_relato(
                    self.server.consultor.normalizar_telefone(numero), categoria)
                self.responder(relato_form(protocolo=protocolo), 201)
            except ValueError as erro:
                self.responder(relato_form(numero, categoria, str(erro)), 400)
        elif self.path == '/mensagem':
            mensagem = campo('mensagem')
            try:
                analise = self.server.consultor.analisar_mensagem(mensagem)
                self.responder(mensagem_form(mensagem, analise))
            except ValueError as erro:
                self.responder(mensagem_form(mensagem[:2000], erro=str(erro)), 400)
        elif self.path == '/entrar':
            agora = monotonic()
            self.server.tentativas = [t for t in self.server.tentativas if agora - t < 60]
            if len(self.server.tentativas) >= 5:
                self.responder(login('Aguarde um minuto antes de tentar novamente.'), 429)
            elif self.server.banco.autenticar(campo('usuario'), campo('senha')):
                token = secrets.token_hex(32)
                self.server.sessao = token, secrets.token_hex(32), agora + 3600
                self.server.tentativas.clear()
                self.ir('/painel', f'moderador={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600')
            else:
                self.server.tentativas.append(agora)
                self.responder(login('Usuário ou senha inválidos.'), 401)
        elif self.path in ('/decidir', '/sair'):
            sessao = self.sessao()
            if not sessao or not compare_digest(campo('csrf').encode(), sessao[1].encode()):
                self.responder('Sessão inválida ou expirada.', 403, tipo='text/plain; charset=utf-8')
            elif self.path == '/sair':
                self.server.sessao = None
                self.ir('/painel', 'moderador=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            else:
                if (re.fullmatch(r'[1-9][0-9]{0,17}', campo('id'))
                        and campo('estado') in ('Aprovado', 'Rejeitado')):
                    self.server.banco.decidir(int(campo('id')), campo('estado'))
                    self.ir('/painel')
                else:
                    self.responder('Decisão inválida.', 400, tipo='text/plain; charset=utf-8')
        else:
            self.responder('Página indisponível.', 404, tipo='text/plain; charset=utf-8')


def main():
    """Inicializa a base e abre o servidor em loopback."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--porta', type=int, default=8765)
    parser.add_argument('--db', default='confere.sqlite3')
    parser.add_argument('--abrir', action='store_true', help='Abre o navegador padrão')
    args = parser.parse_args()
    banco = Banco(args.db)
    try:
        banco.iniciar_moderador(os.environ.get('CONFERE_SENHA_INICIAL'))
        with Servidor(('127.0.0.1', args.porta), banco) as servidor:
            url = f'http://127.0.0.1:{servidor.server_port}'
            print(f'Abra {url} no navegador.', flush=True)
            if args.abrir:
                webbrowser.open(url)
            servidor.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        banco.db.close()


if __name__ == '__main__':
    main()
