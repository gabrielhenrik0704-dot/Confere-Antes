"""Árvore B com páginas de até 31 chaves e métricas por operação."""

from bisect import bisect_left
from dataclasses import dataclass, field

GRAU = 16
MAXIMO = 2 * GRAU - 1


@dataclass(slots=True)
class Pagina:
    """Página com chaves ordenadas e filhos entre essas chaves."""

    chaves: list[str] = field(default_factory=list)
    valores: list[int] = field(default_factory=list)
    filhos: list['Pagina'] = field(default_factory=list)


class IndiceUsuarios:
    """Índice em memória para busca e inserção O(log N)."""

    def __init__(self):
        self.raiz = Pagina()

    def buscar(self, chave):
        """Retorna (identificador ou None, páginas percorridas)."""
        pagina = self.raiz
        visitas = 0
        while True:
            visitas += 1
            posicao = bisect_left(pagina.chaves, chave)
            if posicao < len(pagina.chaves) and pagina.chaves[posicao] == chave:
                return pagina.valores[posicao], visitas
            if not pagina.filhos:
                return None, visitas
            pagina = pagina.filhos[posicao]

    @staticmethod
    def _dividir(pai, posicao):
        """Promove a mediana de um filho cheio e cria sua metade direita."""
        filho = pai.filhos[posicao]
        meio = GRAU - 1
        direita = Pagina(filho.chaves[GRAU:], filho.valores[GRAU:],
                         filho.filhos[GRAU:])
        pai.chaves.insert(posicao, filho.chaves[meio])
        pai.valores.insert(posicao, filho.valores[meio])
        pai.filhos.insert(posicao + 1, direita)
        del filho.chaves[meio:]
        del filho.valores[meio:]
        del filho.filhos[GRAU:]

    def inserir(self, chave, valor):
        """Desce por páginas com espaço, dividindo filhos cheios no caminho."""
        if len(self.raiz.chaves) == MAXIMO:
            self.raiz = Pagina(filhos=[self.raiz])
            self._dividir(self.raiz, 0)

        pagina = self.raiz
        visitas = 0
        while True:
            visitas += 1
            posicao = bisect_left(pagina.chaves, chave)
            if posicao < len(pagina.chaves) and pagina.chaves[posicao] == chave:
                raise ValueError('Chave já cadastrada.')
            if not pagina.filhos:
                pagina.chaves.insert(posicao, chave)
                pagina.valores.insert(posicao, valor)
                return visitas

            if len(pagina.filhos[posicao].chaves) == MAXIMO:
                self._dividir(pagina, posicao)
                promovida = pagina.chaves[posicao]
                if chave == promovida:
                    raise ValueError('Chave já cadastrada.')
                if chave > promovida:
                    posicao += 1
            pagina = pagina.filhos[posicao]
