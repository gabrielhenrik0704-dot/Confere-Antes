"""Benchmark reproduzível do índice de usuários com dados sintéticos."""

import argparse
import math
import random
from statistics import mean
from time import perf_counter_ns

from indice import IndiceUsuarios


def chave(numero):
    """Gera um nome sintético válido de largura fixa."""
    return f'cidadao_{numero:08d}'


def medir(total):
    """Compara visitas e latência do índice com log2 da população inicial."""
    indice = IndiceUsuarios()
    for numero in range(total):
        indice.inserir(chave(2 * numero), numero)

    amostras = random.Random(42).sample(range(total), 2000)
    buscas, insercoes, tempos_busca, tempos_insercao = [], [], [], []
    for numero in amostras:
        termo = chave(2 * numero)
        inicio = perf_counter_ns()
        valor, visitas = indice.buscar(termo)
        tempos_busca.append(perf_counter_ns() - inicio)
        assert valor == numero
        buscas.append(visitas)

    for numero in amostras:
        termo = chave(2 * numero + 1)
        inicio = perf_counter_ns()
        visitas = indice.inserir(termo, total + numero)
        tempos_insercao.append(perf_counter_ns() - inicio)
        insercoes.append(visitas)
        assert indice.buscar(termo)[0] == total + numero

    limite = math.log2(total)
    busca, insercao = mean(buscas), mean(insercoes)
    print(f'{total:>9} | {limite:>7.2f} | {busca:>12.2f} | {insercao:>12.2f} | '
          f'{mean(tempos_busca) / 1000:>8.2f} | {mean(tempos_insercao) / 1000:>10.2f}',
          flush=True)
    if max(busca, insercao) > limite:
        raise SystemExit('A média de páginas visitados ultrapassou log2(N).')


def main():
    """Executa os três cenários de carga exigidos no enunciado."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rapido', action='store_true', help='Executa apenas N=10.000')
    args = parser.parse_args()
    print(' Usuários | log2(N) |  Busca pág.   | Inserção pág. | Busca µs | Inserção µs',
          flush=True)
    for total in ((10_000,) if args.rapido else (10_000, 100_000, 1_000_000)):
        medir(total)


if __name__ == '__main__':
    main()
