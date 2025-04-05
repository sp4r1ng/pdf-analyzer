#!/usr/bin/env python3
import argparse
import re
import sys
import os
import string
import zlib
import codecs
from PyPDF2 import PdfReader

try:
    import jsbeautifier
except ImportError:
    sys.stderr.write("[!] Le module jsbeautifier n'est pas installé. Installez-le avec 'pip install jsbeautifier'\n")
    sys.exit(1)

### Paramètres globaux ###
KEYWORDS_LIST = ["/JS ", "/JavaScript"]
SEPAR_LINE_LEN = 60

SUSPICIOUS_PATTERNS = {
    "JavaScript": [rb"/JavaScript", rb"/JS"],
    "OpenAction": [rb"/OpenAction"],
    "Additional Actions": [rb"/AA"],
    "Embedded Files": [rb"/EmbeddedFile"],
    "RichMedia": [rb"/RichMedia"],
    "Launch": [rb"/Launch"],
    "AcroForm": [rb"/AcroForm"],
}

### Fonctions Utilitaires ###
def is_pdf_document(filename):
    try:
        with open(filename, 'rb') as f:
            header = f.read(1024)
        return b'%PDF' in header
    except Exception as e:
        print(f"[!] Erreur lors de la vérification du fichier : {e}")
        return False

def analyse_brute(pdf_bytes):
    """
    Recherche dans le contenu binaire du PDF des motifs suspects.
    Retourne un dictionnaire indiquant le nombre d'occurrences par indicateur.
    """
    counts = {}
    for key, patterns in SUSPICIOUS_PATTERNS.items():
        count = 0
        for pattern in patterns:
            count += len(re.findall(pattern, pdf_bytes))
        counts[key] = count
    return counts

def analyse_metadonnees(pdf_path):
    """
    Extrait les métadonnées du PDF via PyPDF2.
    Retourne un dictionnaire contenant le nombre de pages, l'état de chiffrement et d'autres infos.
    """
    meta = {}
    try:
        reader = PdfReader(pdf_path)
        meta['nombre_pages'] = len(reader.pages)
        meta['est_chiffre'] = reader.is_encrypted
        meta['infos'] = reader.metadata
    except Exception as e:
        meta['erreur'] = str(e)
    return meta

def evaluer_risque(suspicious_counts):
    """
    Calcule un score de risque pondéré en fonction des indicateurs trouvés.
    Retourne le score total et un verdict.
    """
    poids = {
        "JavaScript": 3,
        "OpenAction": 2,
        "Additional Actions": 2,
        "Embedded Files": 3,
        "RichMedia": 3,
        "Launch": 4,
        "AcroForm": 1,
    }
    score = sum(count * poids.get(key, 1) for key, count in suspicious_counts.items())
    
    if score >= 10:
        verdict = "Haute suspicion de contenu malveillant"
    elif score >= 5:
        verdict = "Suspicion modérée – à analyser plus en détail"
    else:
        verdict = "Apparence généralement saine"
    
    return score, verdict

def find_pattern(filename, pattern, caseSensitivity=False):
    """
    Recherche un pattern donné dans le fichier (similaire à 'grep -a').
    """
    flags = 0 if caseSensitivity else re.IGNORECASE
    regex = re.compile(pattern, flags)
    line_counter, match_counter = 0, 0
    try:
        with open(filename, errors="ignore") as file:
            for line in file:
                line_counter += 1
                for _ in regex.finditer(line):
                    match_counter += 1
                    print(f"[+] Motif '{pattern}' trouvé à la ligne {line_counter} : {line.rstrip()}")
    except Exception as e:
        print(f"[!] Erreur lors de la recherche du motif : {e}")
    if match_counter == 0:
        print(f"[-] Aucun résultat pour le motif '{pattern}'")

def extract_strings(filename, min_length=6):
    """
    Fonction de type 'strings' qui parcourt le fichier et retourne les chaînes
    d'au moins 'min_length' caractères.
    """
    with open(filename, errors="ignore") as file:
        result = ""
        for char in file.read():
            if char in string.printable:
                result += char
            else:
                if len(result) >= min_length:
                    yield result
                result = ""
        if len(result) >= min_length:
            yield result

def unpack_flatedecode_and_extract_text(filename, txtOnly=False):
    """
    Décompresse tous les objets FlateDecode et tente d'extraire le texte qu'ils contiennent.
    """
    try:
        with open(filename, "rb") as file:
            pdf = file.read()
    except Exception as e:
        print(f"[!] Erreur d'ouverture du fichier : {e}")
        return b""
    
    headers = re.compile(rb'.*FlateDecode.*').findall(pdf)
    data_regex = re.compile(rb'.*?FlateDecode.*?stream([\s\S]*?)endstream', re.S)
    regex1 = re.compile(rb'\[(.*?)\]')
    regex2 = re.compile(rb'\((.*?)\)')
    
    extracted_text = b""
    for i, data in enumerate(data_regex.findall(pdf)):
        if not txtOnly:
            print("-" * SEPAR_LINE_LEN)
            if i < len(headers):
                print(f"[*] Objet {i} avec header: {headers[i]}")
            else:
                print(f"[*] Objet {i}")
            print("-" * SEPAR_LINE_LEN)
        
        data = data.strip(b'\r\n')
        try:
            decompressed = zlib.decompress(data)
            if not txtOnly:
                print("[+] Données décompressées :", decompressed)
                print("-" * SEPAR_LINE_LEN + "\n")
        except Exception as e:
            if not txtOnly:
                print("[-] Échec de décompression avec zlib :", e)
                print("-" * SEPAR_LINE_LEN + "\n")
            continue

        for part in regex1.findall(decompressed):
            part = part.replace(b'\\\\', b'BACK_SLSH').replace(b'\\(', b'PAR_OPEN').replace(b'\\)', b'PAR_CLOSE')
            for text_fragment in regex2.findall(part):
                extracted_text += text_fragment

    extracted_text = extracted_text.replace(b'BACK_SLSH', b'\\').replace(b'PAR_OPEN', b'(').replace(b'PAR_CLOSE', b')')
    return extracted_text

def unpack_javascript(pdf, jsObjectID, extractToFile):
    """
    Décompresse et formate le code JavaScript contenu dans l'objet identifié par jsObjectID.
    """
    pattern = jsObjectID + rb' 0 obj[\s\S]*?stream([\s\S]*?)endstream[\s\S]*?obj'
    regex = re.compile(pattern)
    for content in regex.findall(pdf):
        content = content.strip(b'\r\n')
        print("-" * SEPAR_LINE_LEN)
        try:
            decompressed = zlib.decompress(content)
        except Exception as e:
            print("[-] Échec de décompression de l'objet JavaScript :", e)
            print("-" * SEPAR_LINE_LEN + "\n")
            continue

        try:
            js_code = decompressed.decode('utf-8', errors="replace")
        except Exception:
            js_code = str(decompressed)
        beautified = jsbeautifier.beautify(js_code)
        
        if extractToFile:
            base = os.path.splitext(os.path.basename(sys.argv[1]))[0]
            outfile = f"{base}_extracted_{jsObjectID.decode('utf-8')}.js"
            try:
                with open(outfile, "w", encoding="utf-8") as f:
                    f.write(beautified)
                print(f"[+] Code JavaScript sauvegardé dans '{outfile}'")
            except Exception as e:
                print(f"[!] Erreur lors de l'écriture du fichier : {e}")
        print("[+] Code JavaScript extrait :")
        print(beautified)
        print("-" * SEPAR_LINE_LEN + "\n")

def spot_extract_javascript(filename, extractToFile=True):
    """
    Recherche dans le PDF les objets contenant du JavaScript compressé et les extrait.
    """
    try:
        with open(filename, "rb") as file:
            pdf = file.read()
    except Exception as e:
        print(f"[!] Erreur d'ouverture du fichier : {e}")
        return

    regex_header = re.compile(rb'\/JavaScript[\S\s]*?>>')
    regex_id = re.compile(rb'\/JavaScript.*?([1-9][0-9]*).*?>>')
    regex_hex = re.compile(rb'(?<=[<])[0-9A-F]+(?=[>])')
    
    found = False
    for header in regex_header.findall(pdf):
        header_clean = header.replace(b'\r', b'').replace(b'\n', b'')
        if header_clean[-3:] == b'R>>':
            found = True
            js_id = regex_id.findall(header_clean)[0]
            print("-" * SEPAR_LINE_LEN)
            print(f"[+] Objet JavaScript trouvé, ID: {js_id.decode('utf-8')}")
            unpack_javascript(pdf, js_id, extractToFile)
        for hex_str in regex_hex.findall(header_clean):
            found = True
            try:
                decoded = bytes.fromhex(hex_str.decode()).decode('utf-8', errors="replace")
                print(f"[+] Chaîne hex décodée : {decoded}")
            except Exception:
                continue
    if not found:
        print("[-] Aucun code JavaScript détecté dans ce PDF.")

def text_postprocessing(text):
    """
    Effectue un post-traitement sur le texte extrait pour décoder les séquences d'échappement.
    """
    escape_seq_re = re.compile(r'''
        ( \\U........      
        | \\u....          
        | \\x..            
        | \\[0-7]{1,3}     
        | \\N\{[^}]+\}     
        | \\[\\'"abfnrtv]  
        )''', re.UNICODE | re.VERBOSE)
    
    def decode_match(match):
        return codecs.decode(match.group(0), 'unicode-escape', errors="ignore")
    
    return escape_seq_re.sub(decode_match, text)

def analyser_pdf(pdf_path, extract_js=False):
    """
    Fonction principale d'analyse du PDF.
    Affiche les résultats de l'analyse et extrait le code JavaScript si demandé.
    """
    if not os.path.exists(pdf_path):
        print(f"[!] Le fichier '{pdf_path}' n'existe pas.")
        sys.exit(1)
    if not is_pdf_document(pdf_path):
        print("[!] Le fichier ne semble pas être un document PDF valide.")
        sys.exit(1)

    print(f"=== Analyse du PDF : {pdf_path} ===\n")

    # Lecture du fichier en binaire
    try:
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()
    except Exception as e:
        print(f"[!] Erreur lors de la lecture du fichier : {e}")
        sys.exit(1)

    # Analyse brute
    print(">>> Analyse brute (motifs suspects) :")
    suspicious_counts = analyse_brute(pdf_bytes)
    for key, count in suspicious_counts.items():
        print(f" - {key} : {count} occurrence(s)")
    score, verdict = evaluer_risque(suspicious_counts)
    print(f"\nScore de risque total : {score}")
    print(f"Verdict : {verdict}\n")

    # Recherche par pattern (similaire à grep)
    print(">>> Recherche de motifs :")
    for keyword in KEYWORDS_LIST:
        find_pattern(pdf_path, keyword, caseSensitivity=False)
        print("")
    
    # Extraction du texte via FlateDecode
    print(">>> Décompression des objets FlateDecode et extraction du texte :")
    extracted_text = unpack_flatedecode_and_extract_text(pdf_path, txtOnly=False)
    if extracted_text:
        try:
            decoded_text = extracted_text.decode("latin1", errors="replace")
        except Exception:
            decoded_text = str(extracted_text)
        final_text = text_postprocessing(decoded_text)
        print(f"[+] Texte extrait (post-traité) :\n{final_text}\n")
    else:
        print("[-] Aucun texte compressé détecté.\n")

    if extract_js:
        print(">>> Extraction du code JavaScript embarqué :")
        spot_extract_javascript(pdf_path, extractToFile=True)
        print("")

    print(">>> Analyse des métadonnées :")
    meta = analyse_metadonnees(pdf_path)
    if "erreur" in meta:
        print(f"[!] Erreur lors de l'analyse des métadonnées : {meta['erreur']}")
    else:
        print(f" - Nombre de pages : {meta.get('nombre_pages', 'N/A')}")
        print(f" - Document chiffré : {meta.get('est_chiffre', 'N/A')}")
        print(" - Autres informations :")
        infos = meta.get('infos')
        if infos:
            for key, value in infos.items():
                print(f"   • {key} : {value}")
        else:
            print("   Aucune métadonnée trouvée.")

def main():
    parser = argparse.ArgumentParser(
        description="Outil avancé d'analyse de PDF pour détecter des contenus malveillants."
    )
    parser.add_argument("pdf", help="Chemin vers le fichier PDF à analyser")
    parser.add_argument("--js", action="store_true", help="Extraire le code JavaScript embarqué")
    args = parser.parse_args()
    analyser_pdf(args.pdf, extract_js=args.js)

if __name__ == "__main__":
    with open("output.txt", "w", encoding="utf-8") as output_file:
        sys.stdout = output_file
        main()
