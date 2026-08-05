"""
Test de regresión — gaps de detección Tier 1 (regex) encontrados el 2026-07-30
tras un leak real: un informe genético con "Paciente: NOMBRE EN MAYUSCULAS"
pasó sin tokenizar el nombre de la paciente ni del médico.

Ejecutar desde la carpeta privaro-proxy:
    python test_detector_gaps.py

Cubre, en un único run offline (sin red, sin Presidio/NLP — solo Tier 1):
  - Nombres en ALL-CAPS (el bug original)
  - Keywords que faltaban: médico, dr./dra., titular, firmado por
  - Nombres con partículas (de, de la, del...)
  - Nombres de una sola palabra
  - Anti-sobre-captura (no debe tragarse "Empresa", "SA", etc.)
  - Anti-sobre-captura entre líneas (no debe cruzar un salto de línea hacia
    la siguiente etiqueta de un documento tabular)
  - NIE sin prefijo explícito (7 dígitos, distinto del DNI de 8)
  - Nº de historia clínica (formato genérico, no solo SIP/TSI/CIP)
  - Pasaporte español
  - Nº de Seguridad Social (NUSS)
  - IBAN de países distintos de España
  - Regresión: todo lo que ya funcionaba antes sigue funcionando
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from app.services import detector

CASES = [
    # (descripción, texto, tipo_esperado)
    ("Nombre ALL-CAPS + 'Paciente'", "Paciente: JUAN PEREZ GOMEZ", "full_name"),
    ("Nombre Title Case + 'Paciente' (regresión)", "Paciente: Juan Perez Gomez", "full_name"),
    ("Nombre ALL-CAPS + 'Médico'", "Médico: MARIA LOPEZ RUIZ", "full_name"),
    ("Nombre Title Case + 'Dr./Dra.'", "Dr./Dra. Maria Lopez Ruiz", "full_name"),
    ("Nombre con partícula 'de la'", "Cliente: Maria de la Cruz Gomez", "full_name"),
    ("Nombre con guion (apellido compuesto)", "Cliente: Juan Garcia-Perez", "full_name"),
    ("Nombre de una sola palabra", "Cliente: Madonna", "full_name"),
    ("Nombre tras 'Firmado por'", "Firmado por: Juan Perez Gomez", "full_name"),
    ("Nombre tras 'Titular'", "Titular: Juan Perez Gomez", "full_name"),
    ("'Dña.' abreviado + ALL CAPS", "Dña. JUAN PEREZ GOMEZ acude a consulta", "full_name"),
    ("NIE sin prefijo (7 dígitos, no 8)", "Su documento X1234567L fue verificado", "dni"),
    ("NIE con prefijo explícito (regresión)", "NIE: X1234567L", "dni"),
    ("DNI estándar sin prefijo (8 dígitos, regresión)", "Ref 12345678Z entregada", "dni"),
    ("DNI con prefijo (regresión)", "DNI: 12345678Z", "dni"),
    ("Nº de historia clínica (formato genérico)", "Nº de historia: 00183370", "health_record"),
    ("Historia clínica con label distinto", "Historia clínica número 00183370", "health_record"),
    ("Pasaporte ES", "Pasaporte: AAA123456", "passport"),
    ("Nº Seguridad Social ES", "Número de afiliación a la Seguridad Social: 281234567840", "ssn"),
    ("IBAN alemán", "Transferencia a DE89370400440532013000", "iban"),
    ("IBAN francés", "IBAN: FR1420041010050500013M02606", "iban"),
    ("IBAN español (regresión)", "IBAN: ES9121000418450200051332", "iban"),
    ("Email (regresión)", "contacto: ana@empresa.es", "email"),
    ("Teléfono ES (regresión)", "Tel: 677 23 45 67", "phone"),
    ("Tarjeta de crédito (regresión)", "Tarjeta 4111 1111 1111 1111", "credit_card"),
    ("Importe monetario (regresión)", "Importe: 45.200,50 €", "money"),
]


def test_battery() -> int:
    fails = 0
    for desc, text, expected_type in CASES:
        dets = detector.detect(text, use_nlp=False)  # Tier 1 solo — sin red, sin Presidio
        types = [d.type for d in dets]
        ok = expected_type in types
        if not ok:
            fails += 1
        marker = "OK   " if ok else "FALLO"
        values = [text[d.start:d.end] for d in dets]
        print(f"{marker} {desc:<52} esperado={expected_type:<15} obtenido={types} valores={values}")
    return fails


def test_no_overcapture_same_line() -> bool:
    """Un nombre real no debe tragarse una palabra empresarial que le sigue."""
    text = "Cliente: Juan Perez Gomez Empresa SA solicita"
    dets = detector.detect(text, use_nlp=False)
    for d in dets:
        if d.type == "full_name":
            val = text[d.start:d.end]
            leaked_company_word = "Empresa" in val or " SA" in val
            print(f"  Anti-sobre-captura (misma línea): {val!r} — {'FALLO' if leaked_company_word else 'OK'}")
            return not leaked_company_word
    print("  Anti-sobre-captura (misma línea): FALLO (no se detectó ningún nombre)")
    return False


def test_no_overcapture_across_newline() -> bool:
    """Un documento tabular no debe fusionar un nombre con la etiqueta siguiente."""
    text = "Paciente: JUAN PEREZ GOMEZ\nMédico: Dr./Dra. ANA MARTINEZ LOPEZ\nProcedencia: CLINICA EJEMPLO"
    dets = detector.detect(text, use_nlp=False)
    names = [text[d.start:d.end] for d in dets if d.type == "full_name"]
    expected = {"JUAN PEREZ GOMEZ", "ANA MARTINEZ LOPEZ"}
    ok = set(names) == expected
    print(f"  Anti-sobre-captura (entre líneas): nombres={names} — {'OK' if ok else 'FALLO'}")
    return ok


if __name__ == "__main__":
    print("=" * 100)
    print("BATERÍA DE REGRESIÓN — gaps de detección Tier 1 (2026-07-30)")
    print("=" * 100)
    fails = test_battery()

    print()
    print("=" * 100)
    print("ANTI-SOBRE-CAPTURA")
    print("=" * 100)
    ok1 = test_no_overcapture_same_line()
    ok2 = test_no_overcapture_across_newline()

    print()
    total = len(CASES)
    passed = total - fails
    print(f"RESULTADO: {passed}/{total} casos de detección OK, "
          f"anti-sobre-captura: {'OK' if (ok1 and ok2) else 'FALLO'}")

    if fails or not (ok1 and ok2):
        sys.exit(1)
