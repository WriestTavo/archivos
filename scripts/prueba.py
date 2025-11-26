#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Escáner de PDFs en /Publico/Documento/<ID> con búsqueda de palabras clave.

Genera dos CSV:
    - todos_los_pdfs.csv      → todos los PDFs encontrados
    - pdfs_sensibles.csv      → PDFs donde se encontraron keywords

Ajusta:
    BASE_URL, ID_INICIO, ID_FIN
"""

import csv
import time
from io import BytesIO

import requests
from pdfminer.high_level import extract_text

# ==========================
# CONFIGURACIÓN
# ==========================

# Ruta correcta de tus documentos
BASE_URL = "https://intranet.congresoson.gob.mx:82/Publico/Documento/"

# Rango de IDs a revisar (AQUÍ INCLUYE 30035)
ID_INICIO = 1
ID_FIN = 40000

# Palabras clave (case-insensitive)
KEYWORDS = [
     "gustavo soto",
    # "cv",
    # "curriculum",
    # "currículum",
    # "direccion",
    # "dirección",
    # "telefono",
    # "tel.",
    # " tel ",
    # "tel ",
    # "celular",
    # "cel.",
    # " cel ",
    # "cel ",
    # "hijos",
    # "datos personales",
    # "preparación academica",
    # "preparación académica",
    # "curp",
    # "rfc",
]

# CSV de salida
CSV_TODOS = "todos_los_pdfs.csv"
CSV_SENSIBLES = "pdfs_sensibles.csv"

# Límite opcional de tamaño en bytes (None = sin límite)
MAX_PDF_SIZE = 5 * 1024 * 1024  # 5 MB

REQUEST_DELAY = 0.2
REQUEST_TIMEOUT = 15


# ==========================
# FUNCIONES
# ==========================

def es_pdf(resp):
    """Verifica si la respuesta parece ser un PDF."""
    ct = resp.headers.get("Content-Type", "").lower()
    if "application/pdf" in ct:
        return True
    if resp.content.startswith(b"%PDF"):
        return True
    return False


def revisar_id(doc_id):
    """
    Revisa un ID: si existe PDF, devuelve info.
    Si además tiene keywords, devuelve info extra.
    """
    url = f"{BASE_URL}{doc_id}"
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False)
    except requests.RequestException as e:
        print(f"[!] Error ID {doc_id}: {e}")
        return None, None

    if resp.status_code != 200:
        return None, None

    # Límite de tamaño
    if MAX_PDF_SIZE is not None:
        cl = resp.headers.get("Content-Length")
        if cl is not None:
            try:
                size = int(cl)
                if size > MAX_PDF_SIZE:
                    print(f"[-] ID {doc_id}: PDF > {size} bytes, saltando análisis de texto.")
                    return {
                        "id": doc_id,
                        "url": url,
                        "size": size,
                        "text_len": 0,
                        "has_text": False,
                    }, None
            except ValueError:
                pass
        else:
            if len(resp.content) > MAX_PDF_SIZE:
                size = len(resp.content)
                print(f"[-] ID {doc_id}: PDF > {size} bytes, saltando análisis de texto.")
                return {
                    "id": doc_id,
                    "url": url,
                    "size": size,
                    "text_len": 0,
                    "has_text": False,
                }, None

    if not es_pdf(resp):
        return None, None

    print(f"[+] ID {doc_id}: PDF encontrado, extrayendo texto...")

    size_bytes = len(resp.content)
    text = ""
    try:
        pdf_bytes = BytesIO(resp.content)
        text = extract_text(pdf_bytes)
    except Exception as e:
        print(f"[!] Error extrayendo texto ID {doc_id}: {e}")
        text = ""

    text_len = len(text.strip())
    has_text = text_len > 0

    # Registro base de cualquier PDF
    registro_pdf = {
        "id": doc_id,
        "url": url,
        "size": size_bytes,
        "text_len": text_len,
        "has_text": has_text,
    }

    # Si no tiene texto, NO podremos buscar keywords
    if not has_text:
        print(f"    [-] ID {doc_id}: sin texto (posible escaneo).")
        return registro_pdf, None

    # Buscar keywords
    text_lower = text.lower()
    encontradas = []
    for kw in KEYWORDS:
        if kw.lower() in text_lower:
            encontradas.append(kw)

    if not encontradas:
        return registro_pdf, None

    registro_sensible = {
        "id": doc_id,
        "url": url,
        "keywords": ", ".join(sorted(set(encontradas))),
        "text_len": text_len,
    }

    print(f"    [!] ID {doc_id}: contiene palabras clave -> {registro_sensible['keywords']}")

    return registro_pdf, registro_sensible


def main():
    print(f"[+] Escaneando {BASE_URL}<ID> de {ID_INICIO} a {ID_FIN}")
    print(f"[+] Palabras clave: {KEYWORDS}\n")

    todos_pdfs = []
    sensibles = []

    for doc_id in range(ID_INICIO, ID_FIN + 1):
        reg_pdf, reg_sensible = revisar_id(doc_id)
        if reg_pdf:
            todos_pdfs.append(reg_pdf)
        if reg_sensible:
            sensibles.append(reg_sensible)
        time.sleep(REQUEST_DELAY)

    print("\n[+] Escaneo terminado.")
    print(f"[+] Total PDFs encontrados: {len(todos_pdfs)}")
    print(f"[+] PDFs con datos sensibles: {len(sensibles)}")

    # Guardar todos los PDFs
    with open(CSV_TODOS, "w", newline="", encoding="utf-8") as f:
        campos = ["id", "url", "size", "text_len", "has_text"]
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        for r in todos_pdfs:
            w.writerow(r)

    # Guardar solo los sensibles
    with open(CSV_SENSIBLES, "w", newline="", encoding="utf-8") as f:
        campos = ["id", "url", "keywords", "text_len"]
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        for r in sensibles:
            w.writerow(r)

    print(f"[+] CSV generado: {CSV_TODOS}")
    print(f"[+] CSV generado: {CSV_SENSIBLES}")
    print("    - Revisa especialmente los PDFs sin texto: pueden ser CV escaneados.")
    

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
