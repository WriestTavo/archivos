#!/usr/bin/env bash

# ============================
#   Analizar Malware Mictlan
# ============================
#
# Uso:
#   ./mictlan.sh /ruta/al/archivo.exe
#   ./mictlan.sh https://sitio.com/archivo.exe
#
# Descripción:
#   Framework básico de análisis estático para muestras sospechosas.
#   - Crea carpeta del caso
#   - Descarga (si es URL)
#   - Calcula hashes
#   - Extrae strings
#   - Genera reporte inicial
#
# NOTA:
#   No ejecuta la muestra, solo análisis estático.
#   Rellena los hooks marcados con "TODO" para integrar:
#     - YARA
#     - VirusTotal API
#     - Ghidra headless, etc.

set -euo pipefail

# ---------- Colores ----------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

# ---------- Comandos opcionales (no críticos) ----------
# VT_API_KEY  -> para VirusTotal (export VT_API_KEY="tu_api_key")
# GHIDRA_DIR  -> ruta de instalación de Ghidra (por ejemplo /opt/ghidra)

run_cmd_to_file() {
  local cmd="$1"; shift
  local out="$1"; shift
  if command -v "$cmd" >/dev/null 2>&1; then
    info "Ejecutando: $cmd $*"
    "$cmd" "$@" > "$out" 2>&1 || warn "Comando falló: $cmd $*"
  else
    warn "$cmd no está instalado, omitiendo $out"
  fi
}

# ---------- Funciones utilitarias ----------
banner() {
  echo -e "${BLUE}"
  echo "███╗   ███╗██╗ ██████╗████████╗██╗      █████╗ ███╗   ██╗"
  echo "████╗ ████║██║██╔════╝╚══██╔══╝██║     ██╔══██╗████╗  ██║"
  echo "██╔████╔██║██║██║        ██║   ██║     ███████║██╔██╗ ██║"
  echo "██║╚██╔╝██║██║██║        ██║   ██║     ██╔══██║██║╚██╗██║"
  echo "██║ ╚═╝ ██║██║╚██████╗   ██║   ███████╗██║  ██║██║ ╚████║"
  echo "╚═╝     ╚═╝╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
  echo "                 Malware Analyzer - Mictlan"
  echo -e "${RESET}"
}

error() {
  echo -e "${RED}[X]${RESET} $*" >&2
  exit 1
}

info() {
  echo -e "${BLUE}[*]${RESET} $*"
}

ok() {
  echo -e "${GREEN}[+]${RESET} $*"
}

warn() {
  echo -e "${YELLOW}[!]${RESET} $*"
}

# ---------- Checar dependencias mínimas ----------
check_deps() {
  local deps=("file" "strings" "sha256sum" "md5sum" "sha1sum" "curl")
  local missing=0

  for d in "${deps[@]}"; do
    if ! command -v "$d" >/dev/null 2>&1; then
      warn "Dependencia faltante: $d"
      missing=1
    fi
  done

  if [ "$missing" -eq 1 ]; then
    warn "Instala las dependencias mínimas, ejemplo (Debian/Ubuntu):"
    echo "  sudo apt update && sudo apt install -y file binutils coreutils curl"
    error "Faltan dependencias."
  fi
}

# ---------- Detectar si es URL ----------
is_url() {
  local target="$1"
  if [[ "$target" =~ ^https?:// ]]; then
    return 0
  else
    return 1
  fi
}

# ---------- Crear carpeta del caso ----------
create_case_dir() {
  local sample_name="$1"
  local ts
  ts="$(date +'%Y%m%d_%H%M%S')"
  local base_name
  base_name="$(basename "$sample_name")"
  local dir="mictlan_${ts}_${base_name}"
  mkdir -p "$dir"
  echo "$dir"
}

# ---------- Descargar muestra si es URL ----------
download_sample() {
  local url="$1"
  local out_dir="$2"
  local fname
  fname="$(basename "$url")"
  local out_path="${out_dir}/${fname}"

  info "Descargando muestra desde URL..."
  curl -fsSL "$url" -o "$out_path" || error "No se pudo descargar la muestra."
  ok "Muestra descargada en: $out_path"
  echo "$out_path"
}

# ---------- Copiar muestra local ----------
copy_sample() {
  local path="$1"
  local out_dir="$2"
  local fname
  fname="$(basename "$path")"
  local out_path="${out_dir}/${fname}"
  cp "$path" "$out_path" || error "No se pudo copiar la muestra."
  ok "Muestra copiada a: $out_path"
  echo "$out_path"
}

# ---------- Calcular hashes ----------
calc_hashes() {
  local sample="$1"
  local out_dir="$2"

  info "Calculando hashes..."
  {
    echo "=== HASHES ==="
    echo "Archivo: $(basename "$sample")"
    echo
    echo "MD5:    $(md5sum    "$sample" | awk '{print $1}')"
    echo "SHA1:   $(sha1sum   "$sample" | awk '{print $1}')"
    echo "SHA256: $(sha256sum "$sample" | awk '{print $1}')"
    echo
  } | tee "${out_dir}/hashes.txt"
  ok "Hashes guardados en hashes.txt"
}

# ---------- Info básica ----------
basic_info() {
  local sample="$1"
  local out_dir="$2"

  info "Analizando tipo de archivo (file)..."
  file "$sample" | tee "${out_dir}/file_info.txt"

  ok "Info básica guardada en file_info.txt"
}

# ---------- Extraer strings ----------
extract_strings() {
  local sample="$1"
  local out_dir="$2"

  info "Extrayendo strings (esto puede tardar)..."
  strings -a "$sample" > "${out_dir}/strings_all.txt"

  ok "Strings completos en strings_all.txt"

  info "Filtrando strings interesantes (URLs, IPs, dominios, rutas, etc.)..."
  grep -Eoi '(https?://[^[:space:]]+|[a-zA-Z0-9._-]+\.[a-zA-Z]{2,6}|[0-9]{1,3}(\.[0-9]{1,3}){3}|[A-Za-z]:\\[^[:space:]]+)' \
    "${out_dir}/strings_all.txt" | sort -u > "${out_dir}/strings_interesting.txt" || true

  ok "Strings interesantes en strings_interesting.txt"
}

# ---------- UPX / packers ----------
analyze_upx() {
  local sample="$1"
  local out_dir="$2"
  info "Revisando si el archivo está empaquetado (UPX)..."
  if command -v upx >/dev/null 2>&1; then
    upx -t "$sample" > "${out_dir}/upx_test.txt" 2>&1 || true
    ok "Resultado UPX en upx_test.txt"
  else
    warn "upx no instalado, omitiendo prueba de packers."
    echo "upx no instalado" > "${out_dir}/upx_test.txt"
  fi
}

# ---------- FLOSS (strings desofuscadas) ----------
analyze_floss() {
  local sample="$1"
  local out_dir="$2"
  info "Ejecutando FLOSS (si está disponible)..."
  if command -v floss >/dev/null 2>&1; then
    floss "$sample" > "${out_dir}/floss_all.txt" 2>/dev/null || true
    grep -Ei "http://|https://|\.onion|[0-9]{1,3}(\.[0-9]{1,3}){3}|@|\.php|\.asp|\.aspx" \
      "${out_dir}/floss_all.txt" | sort -u > "${out_dir}/floss_iocs.txt" || true
    ok "FLOSS completado: floss_all.txt y floss_iocs.txt"
  else
    warn "floss no instalado, omitiendo análisis desofuscado."
    echo "floss no instalado" > "${out_dir}/floss_all.txt"
  fi
}

# ---------- PEScan (info PE) ----------
analyze_pescan() {
  local sample="$1"
  local out_dir="$2"
  info "Ejecutando PEScan (si está disponible)..."
  if command -v pescan >/dev/null 2>&1; then
    pescan "$sample" > "${out_dir}/pescan.txt" 2>&1 || true
    ok "Resultado PEScan en pescan.txt"
  else
    warn "pescan no instalado, omitiendo análisis PE avanzado."
    echo "pescan no instalado" > "${out_dir}/pescan.txt"
  fi
}

# ---------- rabin2 (radare2) ----------
analyze_rabin2() {
  local sample="$1"
  local out_dir="$2"
  info "Ejecutando rabin2 (radare2) si está instalado..."
  if command -v rabin2 >/dev/null 2>&1; then
    rabin2 -I "$sample" > "${out_dir}/rabin2_info.txt" 2>&1 || true
    rabin2 -z "$sample" > "${out_dir}/rabin2_strings.txt" 2>&1 || true
    ok "Resultados rabin2 en rabin2_info.txt y rabin2_strings.txt"
  else
    warn "rabin2 no instalado, omitiendo análisis adicional."
    echo "rabin2 no instalado" > "${out_dir}/rabin2_info.txt"
  fi
}

# ---------- Entropía del archivo ----------
calc_entropy() {
  local sample="$1"
  local out_dir="$2"
  info "Calculando entropía (python3)..."
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$sample" > "${out_dir}/entropy.txt" << 'EOF'
import math, sys
from collections import Counter

if len(sys.argv) < 2:
    sys.exit("Uso: python script.py <file>")
path = sys.argv[1]
with open(path, "rb") as f:
    data = f.read()

counts = Counter(data)
size = len(data)
if size == 0:
    print(f"File: {path}\nSize: 0 bytes\nEntropy: 0.000000 bits/byte")
    sys.exit(0)

entropy = 0.0
for c in counts.values():
    p = c / size
    entropy -= p * math.log2(p)

print(f"File: {path}")
print(f"Size: {size} bytes")
print(f"Entropy: {entropy:.6f} bits/byte")
EOF
    ok "Entropía calculada en entropy.txt"
  else
    warn "python3 no instalado, no se puede calcular entropía."
    echo "python3 no instalado" > "${out_dir}/entropy.txt"
  fi
}

# ---------- Regla YARA automática ----------
generate_yara_auto() {
  local sample="$1"
  local out_dir="$2"
  local hashes_file="${out_dir}/hashes.txt"
  if [[ ! -f "$hashes_file" ]]; then
    warn "No se encontró hashes.txt, no se puede generar YARA automática."
    return
  fi
  local sha256
  sha256="$(grep -i 'SHA256:' "$hashes_file" | awk '{print $2}')"
  if [[ -z "$sha256" ]]; then
    warn "No se pudo extraer SHA256 de hashes.txt"
    return
  fi
  local rule_name="mictlan_${sha256:0:12}"
  local yara_file="${out_dir}/${rule_name}.yara"

  info "Generando regla YARA automática: $rule_name"

  {
    echo "rule ${rule_name} {"
    echo "  meta:"
    echo "    description = \"Regla auto-generada por Mictlan para hash ${sha256}\""
    echo "    sha256 = \"${sha256}\""
    echo
    echo "  strings:"
    if [[ -f "${out_dir}/strings_interesting.txt" ]]; then
      nl -w2 -s' ' "${out_dir}/strings_interesting.txt" | head -n 10 | while read -r n s; do
        clean="$(echo "$s" | tr -d '\r' | sed 's/"/\\"/g')"
        echo "    \$s${n} = \"${clean}\" ascii nocase"
      done
    fi
    if [[ -f "${out_dir}/floss_iocs.txt" ]]; then
      nl -w2 -s' ' "${out_dir}/floss_iocs.txt" | head -n 10 | while read -r n s; do
        clean="$(echo "$s" | tr -d '\r' | sed 's/"/\\"/g')"
        echo "    \$f${n} = \"${clean}\" ascii nocase"
      done
    fi
    echo
    echo "  condition:"
    echo "    sha256(0, filesize) == \"${sha256}\" or any of them"
    echo "}"
  } > "$yara_file"

  ok "Regla YARA generada: $(basename "$yara_file")"
}

# ---------- VirusTotal (opcional) ----------
vt_lookup() {
  local out_dir="$1"
  local hashes_file="${out_dir}/hashes.txt"
  if [[ -z "${VT_API_KEY:-}" ]]; then
    warn "VT_API_KEY no definido, omitiendo consulta a VirusTotal."
    return
  fi
  if [[ ! -f "$hashes_file" ]]; then
    warn "No se encontró hashes.txt para VirusTotal."
    return
  fi
  local sha256
  sha256="$(grep -i 'SHA256:' "$hashes_file" | awk '{print $2}')"
  if [[ -z "$sha256" ]]; then
    warn "No se pudo extraer SHA256 de hashes.txt para VT."
    return
  fi

  info "Consultando VirusTotal para SHA256: $sha256"
  local vt_out="${out_dir}/virustotal_${sha256}.json"
  curl -s \
    --request GET \
    --url "https://www.virustotal.com/api/v3/files/${sha256}" \
    --header "x-apikey: ${VT_API_KEY}" \
    -o "$vt_out"

  ok "Respuesta de VirusTotal guardada en: $(basename "$vt_out")"
}

# ---------- Ghidra headless (opcional) ----------
ghidra_headless_net() {
  local sample="$1"
  local out_dir="$2"
  if [[ -z "${GHIDRA_DIR:-}" ]]; then
    warn "GHIDRA_DIR no definido, omitiendo análisis headless."
    return
  fi
  if [[ ! -d "$GHIDRA_DIR" ]]; then
    warn "GHIDRA_DIR no es un directorio válido: $GHIDRA_DIR"
    return
  fi

  info "Ejecutando Ghidra headless para buscar APIs de red..."
  local project_dir="${out_dir}/ghidra_project"
  local project_name="Mictlan_$(basename "$sample")"
  local script_dir="${out_dir}/ghidra_scripts"
  mkdir -p "$project_dir" "$script_dir"

  local ghidra_py="${script_dir}/find_network_functions.py"

  cat > "$ghidra_py" << 'EOF'
from ghidra.program.model.symbol import SymbolUtilities

TARGET_APIS = [
    "connect",
    "WSAStartup",
    "InternetOpenA",
    "InternetConnectA",
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
]

def main():
    currentProgram = getCurrentProgram()
    fm = currentProgram.getFunctionManager()

    println("[+] Buscando funciones que llamen a APIs de red...")
    println("[+] APIs objetivo: {}".format(", ".join(TARGET_APIS)))

    for api in TARGET_APIS:
        symbols = SymbolUtilities.getSymbols(api, currentProgram)
        if not symbols:
            continue

        for sym in symbols:
            api_addr = sym.getAddress()
            println("\n[+] API encontrada: {} @ {}".format(api, api_addr))
            refs = getReferencesTo(api_addr)
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                if func is not None:
                    println("    - Llamada desde función: {} @ {}".format(
                        func.getName(), func.getEntryPoint()))
                else:
                    println("    - Llamada desde: {}".format(from_addr))

if __name__ == "__main__":
    main()
EOF

  "${GHIDRA_DIR}/support/analyzeHeadless" "$project_dir" "$project_name" \
    -import "$sample" \
    -scriptPath "$script_dir" \
    -postScript "$(basename "$ghidra_py")" \
    > "${out_dir}/ghidra_headless.log" 2>&1 || warn "Ghidra headless terminó con errores (ver ghidra_headless.log)"

  ok "Log de Ghidra headless: ghidra_headless.log"
}

# ---------- Template reporte inicial ----------
generate_report() {
  local sample="$1"
  local case_dir="$2"

  local report="${case_dir}/reporte_mictlan.txt"
  ok "Generando reporte inicial: $report"

  {
    echo "# ============================"
    echo "#   Analizar Malware Mictlan"
    echo "# ============================"
    echo
    echo "Fecha: $(date)"
    echo "Archivo analizado: $(basename "$sample")"
    echo "Ruta: $sample"
    echo "Caso: $(basename "$case_dir")"
    echo
    echo "## 1. Hashes"
    echo "Ver: hashes.txt"
    echo
    echo "## 2. Información básica (file)"
    echo "Ver: file_info.txt"
    echo
    echo "## 3. Strings interesantes"
    echo "Ver: strings_interesting.txt"
    echo
    echo "## 4. Análisis adicional (si herramientas instaladas)"
    echo "- UPX: upx_test.txt"
    echo "- FLOSS: floss_all.txt y floss_iocs.txt"
    echo "- PEScan: pescan.txt"
    echo "- rabin2: rabin2_info.txt y rabin2_strings.txt"
    echo "- Entropía: entropy.txt"
    echo
    echo "## 5. Regla YARA auto-generada"
    echo "- Ver: *.yara (regla creada a partir del SHA256 y strings)"
    echo
    echo "## 6. VirusTotal (opcional)"
    echo "- Si VT_API_KEY está definido se genera: virustotal_<SHA256>.json"
    echo
    echo "## 7. Ghidra headless (opcional)"
    echo "- Si GHIDRA_DIR está definido se genera: ghidra_headless.log"
    echo
    echo "## 8. Observaciones manuales"
    echo "- Anotar hallazgos relevantes:"
    echo "  * Posibles C2, dominios, IPs, URLs sospechosas"
    echo "  * Rutas internas, nombres de usuario, mensajes de error"
    echo "  * Librerías sospechosas o empaquetadores (UPX, ASPack, etc.)"
    echo
    echo "Fin del reporte inicial Mictlan."
  } > "$report"
}

# ---------- MAIN ----------
main() {
  banner
  check_deps

  if [ "$#" -ne 1 ]; then
    echo "Uso: $0 <ruta-o-URL-del-archivo>"
    exit 1
  fi

  local target="$1"

  # Crear carpeta de caso (usa el nombre del target tal cual)
  local case_dir
  case_dir="$(create_case_dir "$target")"
  ok "Carpeta del caso: $case_dir"

  # Obtener muestra dentro de la carpeta
  local sample_path
  if is_url "$target"; then
    sample_path="$(download_sample "$target" "$case_dir")"
  else
    [ -f "$target" ] || error "El archivo no existe: $target"
    sample_path="$(copy_sample "$target" "$case_dir")"
  fi

  # Análisis
  calc_hashes     "$sample_path" "$case_dir"
  basic_info      "$sample_path" "$case_dir"
  extract_strings "$sample_path" "$case_dir"

  analyze_upx       "$sample_path" "$case_dir"
  analyze_floss     "$sample_path" "$case_dir"
  analyze_pescan    "$sample_path" "$case_dir"
  analyze_rabin2    "$sample_path" "$case_dir"
  calc_entropy      "$sample_path" "$case_dir"
  generate_yara_auto "$sample_path" "$case_dir"
  vt_lookup         "$case_dir"
  ghidra_headless_net "$sample_path" "$case_dir"

  generate_report "$sample_path" "$case_dir"

  echo
  ok "Análisis Mictlan completado."
  echo "Revisa la carpeta: $case_dir"
  echo "Archivos clave:"
  echo "  - hashes.txt"
  echo "  - file_info.txt"
  echo "  - strings_all.txt"
  echo "  - strings_interesting.txt"
  echo "  - reporte_mictlan.txt"
  echo
}

main "$@"