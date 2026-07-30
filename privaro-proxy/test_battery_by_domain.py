"""
Batería de QA de detección PII/PHI por ámbito de negocio (2026-07-30).

Objetivo: tras el fix de gaps de Tier 1 (PR #2), verificar de forma
sistemática que los formatos habituales de cada sector (finanzas, RRHH,
seguros, legal, sanidad, telecomunicaciones) se detectan correctamente,
y descubrir cualquier gap NUEVO no cubierto por ese fix.

Todos los datos son sintéticos/ficticios — ningún dato real de cliente,
paciente ni empleado.

Metodología: cada documento lleva una lista de "ground truth" —
(tipo_esperado, substring_exacto) — uno por cada dato sensible incrustado
deliberadamente. Se corre detector.detect() (Tier 1, sin red/Presidio,
igual que corre siempre como base garantizada) y se comprueba que cada
substring esperado quede cubierto por una detección del tipo correcto.

Ejecutar:
    python3 test_battery_by_domain.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from app.services import detector


def covered(detections, text, expected_type, expected_substr):
    """¿Hay alguna detección del tipo esperado cuyo span cubra (o se
    solape sustancialmente con) el substring esperado?"""
    idx = text.find(expected_substr)
    if idx == -1:
        return None  # error de test: el substring ni siquiera está en el texto
    s_start, s_end = idx, idx + len(expected_substr)
    for d in detections:
        if d.type != expected_type:
            continue
        # solapamiento (no necesariamente exacto, basta con que se toquen
        # de forma sustancial, ya que el objetivo es "se protegió o no")
        overlap = max(0, min(d.end, s_end) - max(d.start, s_start))
        if overlap >= max(1, int(len(expected_substr) * 0.6)):
            return True
    return False


DOMAINS = {}

# ─────────────────────────────────────────────────────────────────────────
DOMAINS["FINANZAS (banca / hipotecas)"] = {
    "text": """
SOLICITUD DE PRÉSTAMO HIPOTECARIO — ENTIDAD FICTICIA BANK, S.A.

Solicitante: RAMONA ORTEGA VILLAR
DNI: 45678912Q
Fecha de nacimiento: 03/11/1985
Domicilio: Avenida de la Constitución 44, 2ºA, 46003 Valencia
Teléfono de contacto: 655 44 33 22
Email: ramona.ortega@correofalso.com

Cotitular: Javier de la Fuente Molina
NIE: Y7654321M

DATOS DE LA OPERACIÓN
Importe solicitado: 185.000,00 €
IBAN de domiciliación: ES7620770024003102575766
Nómina mensual neta: 2.340,00 €
Tarjeta asociada para gastos: 5412 7512 3412 3456

El solicitante Sr./Sra. Ramona Ortega Villar declara que los ingresos
declarados son ciertos, y firma la presente solicitud junto con su
cotitular Javier de la Fuente Molina.

Firmado por: Ramona Ortega Villar
""",
    "ground_truth": [
        ("full_name", "RAMONA ORTEGA VILLAR"),
        ("dni", "45678912Q"),
        ("phone", "655 44 33 22"),
        ("email", "ramona.ortega@correofalso.com"),
        ("full_name", "Javier de la Fuente Molina"),
        ("dni", "Y7654321M"),  # NIE
        ("money", "185.000,00 €"),
        ("iban", "ES7620770024003102575766"),
        ("money", "2.340,00 €"),
        ("credit_card", "5412 7512 3412 3456"),
    ],
}

# ─────────────────────────────────────────────────────────────────────────
DOMAINS["RRHH (contrato laboral / nómina)"] = {
    "text": """
CONTRATO DE TRABAJO INDEFINIDO

Empresa: TECNOLOGIAS INNOVADORAS DEL LEVANTE SL, con CIF B12345678
Trabajador: MOHAMED EL AMRANI BENJELLOUN
NIE: X1234567L
Nº Seguridad Social: 46 1234567 80
Domicilio: Calle Ruzafa 8, 3º, 46004 Valencia
Teléfono: 611223344
Email corporativo: m.elamrani@empresaficticia.com

Puesto: Ingeniero de Software Senior
Fecha de inicio: 01/09/2026
Salario bruto anual: 52.000,00 €
Cuenta de abono de nómina — IBAN: ES1000491500051234567892

Cláusula de confidencialidad firmada por Doña Elena Castro Vidal
(Directora de RRHH) y por el trabajador arriba indicado.

En caso de baja médica, el trabajador deberá presentar el parte de baja
con su número de historia clínica correspondiente al Servicio de
Prevención: Nº de historia: 88213045
""",
    "ground_truth": [
        ("full_name", "MOHAMED EL AMRANI BENJELLOUN"),
        ("dni", "X1234567L"),  # NIE
        ("ssn", "46 1234567 80"),
        ("phone", "611223344"),
        ("email", "m.elamrani@empresaficticia.com"),
        ("money", "52.000,00 €"),
        ("iban", "ES1000491500051234567892"),
        ("full_name", "Elena Castro Vidal"),
        ("health_record", "88213045"),
    ],
}

# ─────────────────────────────────────────────────────────────────────────
DOMAINS["SEGUROS (parte de siniestro)"] = {
    "text": """
PARTE DE DECLARACIÓN DE SINIESTRO — PÓLIZA MULTIRRIESGO HOGAR

Asegurado: FRANCISCO JAVIER MORENO SANTOS
DNI: 87654321X
Nº de póliza: HOG-2026-0093482
Domicilio del riesgo: Plaza del Ayuntamiento 3, 1ºC, 03001 Alicante
Teléfono: 699887766
Email: fj.moreno@correoficticio.net

DESCRIPCIÓN DEL SINIESTRO
Con fecha 14/06/2026 se produjo una inundación en el domicilio del
asegurado, Don Francisco Javier Moreno Santos, ocasionando daños en el
mobiliario y en el suelo de la vivienda.

DATOS PARA LA INDEMNIZACIÓN
IBAN para el reembolso: ES9000751234563456789012
Importe estimado de la indemnización: 3.750,50 €

Perito asignado: Dña. CARMEN IGLESIAS PRADO
Contacto del perito: 622334455

El asegurado adjunta copia de su DNI (87654321X) y de la Tarjeta
Sanitaria (TSI: AB12345678) por la asistencia médica recibida tras el
siniestro.
""",
    "ground_truth": [
        ("full_name", "FRANCISCO JAVIER MORENO SANTOS"),
        ("dni", "87654321X"),
        ("phone", "699887766"),
        ("email", "fj.moreno@correoficticio.net"),
        ("full_name", "Francisco Javier Moreno Santos"),
        ("iban", "ES9000751234563456789012"),
        ("money", "3.750,50 €"),
        ("full_name", "CARMEN IGLESIAS PRADO"),
        ("phone", "622334455"),
        ("health_record", "AB12345678"),  # TSI
    ],
}

# ─────────────────────────────────────────────────────────────────────────
DOMAINS["LEGAL (poder notarial / contrato)"] = {
    "text": """
ESCRITURA DE PODER GENERAL PARA PLEITOS

Ante mí, el Notario del Ilustre Colegio de Madrid, COMPARECE:

De una parte, Don ANTONIO RUIZ FERNANDEZ, mayor de edad, con DNI
número 11223344B, con domicilio en Calle Serrano 120, 4º Izq, 28006
Madrid, y de estado civil casado.

De otra parte, Doña LAURA GIMENEZ CORTES, con DNI 99887766C, actuando
en representación de la mercantil ASESORIA LEGAL INTEGRAL SLP.

EXPONEN
Que el compareciente Antonio Ruiz Fernandez otorga poder general para
pleitos a favor de Laura Gimenez Cortes, quien podrá actuar en su
nombre y representación ante cualquier Juzgado o Tribunal.

Como forma de pago de los honorarios profesionales, se domicilia en
la cuenta IBAN ES4201824567890201234567 el importe de 1.200,00 €.

Firmado ante Notario, en Madrid, a 30 de julio de 2026.

Testigo: Sr. PEDRO SANCHEZ DE LA TORRE
""",
    "ground_truth": [
        ("full_name", "ANTONIO RUIZ FERNANDEZ"),
        ("dni", "11223344B"),
        ("full_name", "LAURA GIMENEZ CORTES"),
        ("dni", "99887766C"),
        ("full_name", "Antonio Ruiz Fernandez"),
        ("full_name", "Laura Gimenez Cortes"),
        ("iban", "ES4201824567890201234567"),
        ("money", "1.200,00 €"),
        ("full_name", "PEDRO SANCHEZ DE LA TORRE"),
    ],
}

# ─────────────────────────────────────────────────────────────────────────
DOMAINS["SANIDAD (informe de alta hospitalaria)"] = {
    "text": """
INFORME DE ALTA HOSPITALARIA

Paciente: TERESA ALVAREZ MOLINA
Nº de historia: 55019287
Fecha de nacimiento: 22/01/1958
Médico responsable: Dr./Dra. RICARDO PENA SOLIS
Servicio: Cardiología

Dña. Teresa Alvarez Molina ingresó el 20/07/2026 por dolor torácico
agudo. Se realizó cateterismo cardíaco sin incidencias. Se implantó un
stent en la arteria coronaria derecha.

Tratamiento al alta: Ácido acetilsalicílico 100mg, Atorvastatina 40mg.

Contacto de familiar responsable: José Antonio Molina Ruiz, teléfono
633445566, email jose.molina@correoficticio.es

Nº Tarjeta Sanitaria (SIP): SIP: CD98765432

Se recomienda revisión en consultas externas de Cardiología en 4
semanas. Cualquier incidencia, contactar al 900112233.
""",
    "ground_truth": [
        ("full_name", "TERESA ALVAREZ MOLINA"),
        ("health_record", "55019287"),
        ("full_name", "RICARDO PENA SOLIS"),
        ("full_name", "Teresa Alvarez Molina"),
        ("full_name", "José Antonio Molina Ruiz"),
        ("phone", "633445566"),
        ("email", "jose.molina@correoficticio.es"),
        ("health_record", "CD98765432"),  # SIP
    ],
}

# ─────────────────────────────────────────────────────────────────────────
DOMAINS["TELECOMUNICACIONES (alta de línea)"] = {
    "text": """
CONTRATO DE ALTA DE LÍNEA MÓVIL Y FIBRA

Titular de la línea: SANDRA JIMENEZ PASCUAL
DNI: 33445566P
Domicilio de instalación: Calle Alcalá 200, 5ºB, 28028 Madrid
Teléfono de contacto: 688990011
Email: sandra.jimenez@correoficticio.org

Número de línea a portar: 622334488
Operador donante: Compañía Telefónica Ficticia SA

DATOS DE DOMICILIACIÓN BANCARIA
IBAN: ES3300491234563456789013
Titular de la cuenta: Sandra Jimenez Pascual

En caso de impago, la compañía podrá suspender el servicio previa
notificación al cliente Dña. Sandra Jimenez Pascual a través del email
o teléfono facilitados.

Atendido por: Carlos Herrera Nuñez (agente comercial), ext. 4521
""",
    "ground_truth": [
        ("full_name", "SANDRA JIMENEZ PASCUAL"),
        ("dni", "33445566P"),
        ("phone", "688990011"),
        ("email", "sandra.jimenez@correoficticio.org"),
        ("phone", "622334488"),
        ("iban", "ES3300491234563456789013"),
        ("full_name", "Sandra Jimenez Pascual"),
        ("full_name", "Carlos Herrera Nuñez"),
    ],
}

# ─────────────────────────────────────────────────────────────────────────

def run():
    grand_total = 0
    grand_ok = 0
    all_gaps = []

    for domain, spec in DOMAINS.items():
        text = spec["text"]
        gt = spec["ground_truth"]
        detections = detector.detect(text, use_nlp=False)

        print("=" * 100)
        print(domain)
        print("=" * 100)
        domain_ok = 0
        for expected_type, expected_substr in gt:
            result = covered(detections, text, expected_type, expected_substr)
            grand_total += 1
            if result is None:
                marker = "ERROR-TEST"
            elif result:
                marker = "OK"
                domain_ok += 1
                grand_ok += 1
            else:
                marker = "GAP"
                all_gaps.append((domain, expected_type, expected_substr))
            print(f"  [{marker:<10}] {expected_type:<14} {expected_substr!r}")

        # Detecciones "extra" no esperadas explícitamente (informativo, no es un fallo)
        expected_substrs = {s for _, s in gt}
        extra = [d for d in detections
                 if text[d.start:d.end] not in expected_substrs
                 and not any(text[d.start:d.end] in s or s in text[d.start:d.end] for s in expected_substrs)]
        if extra:
            print(f"  (detecciones adicionales no anotadas en ground truth, informativo):")
            for d in extra:
                print(f"      + {d.type}: {text[d.start:d.end]!r}")

        print(f"  -> {domain_ok}/{len(gt)} datos sensibles de este ámbito protegidos correctamente")
        print()

    print("=" * 100)
    print(f"RESULTADO GLOBAL: {grand_ok}/{grand_total} datos sensibles detectados correctamente en Tier 1")
    print("=" * 100)
    if all_gaps:
        print("\nGAPS ENCONTRADOS:")
        for domain, t, s in all_gaps:
            print(f"  - [{domain}] tipo esperado={t}, valor no protegido={s!r}")
    else:
        print("\nSin gaps — todos los datos sensibles anotados fueron detectados.")

    return all_gaps


if __name__ == "__main__":
    gaps = run()
    sys.exit(1 if gaps else 0)
