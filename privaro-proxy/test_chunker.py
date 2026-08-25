"""
Test de regresión — chunker.py (Privaro Ingest, Fase 1 del plan de RAG).

INVARIANTE CRÍTICO bajo prueba: ningún chunk debe partir un token
[XX-0001] a mitad. Ver chunker.py's module docstring para el porqué —
es la misma clase de bug (nombre partido entre líneas) que costó horas
encontrar y arreglar en el propio detector, aplicada ahora a los
límites de chunk.

Ejecutar:
    python3 test_chunker.py
"""
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from app.services.chunker import chunk_protected_document, _TOKEN_RE


def verificar(texto: str, chunks) -> None:
    reconstruido = "".join(c.text for c in chunks)
    assert reconstruido == texto, f"Reconstrucción rota: {len(reconstruido)} vs {len(texto)} chars"
    for i, c in enumerate(chunks):
        assert c.index == i
        assert texto[c.char_start:c.char_end] == c.text
        if i > 0:
            assert c.char_start == chunks[i - 1].char_end, "Hueco o solape entre chunks"
    if chunks:
        assert chunks[0].char_start == 0
        assert chunks[-1].char_end == len(texto)

    tokens_originales = [(m.start(), m.end()) for m in _TOKEN_RE.finditer(texto)]
    limites_chunk = set()
    for c in chunks:
        limites_chunk.add(c.char_start)
        limites_chunk.add(c.char_end)
    for t_start, t_end in tokens_originales:
        for limite in limites_chunk:
            assert not (t_start < limite < t_end), f"Token partido: span=({t_start},{t_end}) límite={limite}"


def test_documento_repetitivo() -> bool:
    bloque = "El paciente [NM-0001] fue atendido por [NM-0002] en [HC-0001]. "
    texto = bloque * 200
    for chunk_size in [10, 20, 30, 50, 64, 100, 128, 200, 512, 1000]:
        chunks = chunk_protected_document(texto, chunk_size=chunk_size)
        verificar(texto, chunks)
    print(f"  Documento repetitivo ({len(texto)} chars, 10 tamaños de chunk): OK")
    return True


def test_sin_tokens() -> bool:
    texto = "Lorem ipsum dolor sit amet. " * 100
    for chunk_size in [50, 128, 512]:
        chunks = chunk_protected_document(texto, chunk_size=chunk_size)
        verificar(texto, chunks)
    print("  Sin tokens (texto plano): OK")
    return True


def test_solo_tokens_pegados() -> bool:
    """Peor caso adversarial: sin ningún punto de corte natural en absoluto."""
    texto = "".join(f"[NM-{i:04d}]" for i in range(500))
    for chunk_size in [5, 9, 10, 15, 20, 50]:
        chunks = chunk_protected_document(texto, chunk_size=chunk_size)
        verificar(texto, chunks)
    print(f"  Solo tokens pegados ({len(texto)} chars, sin cortes naturales): OK")
    return True


def test_casos_limite() -> bool:
    assert chunk_protected_document("", chunk_size=100) == []
    assert len(chunk_protected_document("a", chunk_size=100)) == 1
    assert len(chunk_protected_document("hola mundo", chunk_size=1000)) == 1
    assert len(chunk_protected_document("hola", chunk_size=1)) == 4
    try:
        chunk_protected_document("hola", chunk_size=0)
        raise AssertionError("chunk_size=0 debería lanzar ValueError")
    except ValueError:
        pass
    print("  Casos límite (vacío, 1 char, chunk_size>doc, chunk_size=1, chunk_size=0): OK")
    return True


def test_fuzz_aleatorio(n_trials: int = 200) -> bool:
    random.seed(7)
    fails = 0
    for trial in range(n_trials):
        n_tokens = random.randint(0, 30)
        partes = []
        for i in range(n_tokens):
            partes.append("".join(random.choice("abcdefg ") for _ in range(random.randint(0, 15))))
            partes.append(f"[{random.choice(['NM', 'ID', 'EM', 'PH', 'HC'])}-{i:04d}]")
        partes.append("".join(random.choice("abcdefg ") for _ in range(random.randint(0, 15))))
        texto = "".join(partes)
        if not texto:
            continue
        chunk_size = random.randint(1, max(2, len(texto)))
        try:
            chunks = chunk_protected_document(texto, chunk_size=chunk_size)
            verificar(texto, chunks)
        except AssertionError as e:
            fails += 1
            print(f"  FALLO trial={trial}: {e} — texto={texto!r} chunk_size={chunk_size}")
    print(f"  Fuzz aleatorio ({n_trials} pruebas): {n_trials - fails}/{n_trials} OK")
    return fails == 0


if __name__ == "__main__":
    print("=" * 100)
    print("TEST DEL CHUNKER — Privaro Ingest (Fase 1 del plan de RAG)")
    print("=" * 100)
    resultados = [
        test_documento_repetitivo(),
        test_sin_tokens(),
        test_solo_tokens_pegados(),
        test_casos_limite(),
        test_fuzz_aleatorio(),
    ]
    if all(resultados):
        print("\nTODOS LOS TESTS PASARON")
    else:
        print("\nALGÚN TEST FALLÓ")
        sys.exit(1)
