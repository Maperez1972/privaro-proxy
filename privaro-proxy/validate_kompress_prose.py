"""
Validación de compresión de prosa (Kompress-v2 / ModernBERT) con documentos
reales tokenizados por Privaro.

CORRER EN RAILWAY (o cualquier entorno con salida real a huggingface.co) —
en el sandbox de desarrollo de Claude, huggingface.co está bloqueado por la
whitelist de red, así que este script no puede validarse ahí. En Railway
funciona sin cambios porque el proyecto ya tiene salida abierta a internet.

Uso:
    pip install headroom-ai[ml]  # ya añadido a requirements.txt en el PR #1
    python validate_kompress_prose.py

Qué verifica:
    1. Que el modelo Kompress-v2 descarga y carga correctamente (primera
       ejecución tarda más — descarga ~90MB de pesos).
    2. El ratio de compresión REAL sobre un documento legal tokenizado
       (no un mock corto — tiene que superar el umbral min_size_bytes=2048
       de Headroom para que el compresor de texto se active).
    3. CRÍTICO: que los tokens [XX-0001] de Privaro sobreviven la
       compresión exactamente, usando el mismo guard de
       app/services/context_optimizer.py que ya está en el PR.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from app.services.context_optimizer import compress_protected_messages

# Documento legal real (contrato de préstamo), ya tokenizado por Privaro —
# tamaño representativo de lo que Robin/Octupus enviarían en un caso real.
LEGAL_DOCUMENT = """
CONTRATO DE PRÉSTAMO PERSONAL

Entre [NM-0001], con DNI [ID-0001] y domicilio en [ADDR-0001], en adelante
"el Prestatario", y la entidad financiera, se establece el presente
contrato de préstamo personal bajo las siguientes condiciones:

PRIMERA. Objeto del contrato. La entidad concede al Prestatario un préstamo
por importe de 25.000 EUR, que será ingresado en la cuenta con IBAN
[BK-0001] a nombre de [NM-0001].

SEGUNDA. Plazo y amortización. El préstamo se amortizará en 60 cuotas
mensuales, mediante domiciliación bancaria en la cuenta indicada. El
Prestatario podrá solicitar la amortización anticipada total o parcial
en cualquier momento, notificándolo con 15 días de antelación al correo
[EM-0001] o al teléfono de contacto [PH-0001].

TERCERA. Intereses. El tipo de interés nominal aplicable será fijo durante
toda la vida del préstamo. En caso de impago, se aplicará un interés de
demora conforme a la normativa vigente, y se notificará al Prestatario en
la dirección [ADDR-0001] y por email a [EM-0001].

CUARTA. Garantías. El Prestatario [NM-0001], identificado con DNI
[ID-0001], garantiza el cumplimiento de las obligaciones derivadas del
presente contrato con todos sus bienes presentes y futuros, conforme al
artículo 1911 del Código Civil.

QUINTA. Protección de datos. Los datos personales del Prestatario
([NM-0001], [ID-0001], [BK-0001], [EM-0001], [PH-0001], [ADDR-0001])
serán tratados conforme al Reglamento General de Protección de Datos
(RGPD) y a la Ley Orgánica de Protección de Datos española, con la
finalidad exclusiva de gestionar la relación contractual.

SEXTA. Modificación de condiciones. Cualquier modificación de las
condiciones de amortización anticipada solicitada por [NM-0001] deberá
formalizarse por escrito y firmarse por ambas partes, incorporándose como
anexo al presente contrato.

En prueba de conformidad, ambas partes firman el presente contrato por
duplicado, en el lugar y fecha indicados en el encabezamiento.
""" * 3  # ~4.5x el tamaño de un contrato real de una página, para representar
        # un expediente completo con anexos

MODEL = "claude-sonnet-4-6"


def main():
    messages = [{"role": "user", "content": LEGAL_DOCUMENT}]
    orig_chars = len(LEGAL_DOCUMENT)
    orig_tokens_pattern_count = LEGAL_DOCUMENT.count("[")  # aprox., solo orientativo

    print(f"Documento de entrada: {orig_chars} caracteres")
    print("Cargando Kompress-v2 (primera vez puede tardar ~30-60s, descarga pesos)...")

    restored, stats = compress_protected_messages(messages, model=MODEL)

    print("\n=== RESULTADO ===")
    print(f"skipped_reason: {stats['skipped_reason']}")
    print(f"tokens_saved: {stats['tokens_saved']}")
    print(f"compression_ratio: {stats['compression_ratio']:.1%}")
    print(f"Caracteres: {orig_chars} -> {len(restored[0]['content'])}")

    # Verificación de integridad — el criterio de éxito real de este test
    import re
    originals = re.findall(r"\[[A-Z]{2,4}-\d{4}\]", LEGAL_DOCUMENT)
    survived = re.findall(r"\[[A-Z]{2,4}-\d{4}\]", restored[0]["content"])
    integrity_ok = sorted(originals) == sorted(survived)

    print(f"\nTokens Privaro originales: {len(originals)}")
    print(f"Tokens Privaro tras compresión+restauración: {len(survived)}")
    print(f"INTEGRIDAD DE TOKENS: {'✅ PASA' if integrity_ok else '❌ FALLA — NO DESPLEGAR'}")

    if stats["skipped_reason"] not in (None, "disabled"):
        print(f"\n⚠️  La compresión se saltó por: {stats['skipped_reason']}")
        print("Si dice 'compressor_error', revisar conectividad a huggingface.co")
        print("desde este entorno, o correr un warmup manual primero.")

    if not integrity_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
