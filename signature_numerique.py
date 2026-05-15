"""
=============================================================
  SIGNATURE NUMÉRIQUE DÉTACHÉE — sur n'importe quel fichier
  Propriétés : Intégrité · Authenticité · Non-répudiation
=============================================================
  Algorithme : RSA-PSS 2048 bits + SHA-256
  Signature détachée : le fichier original n'est PAS modifié.
  La signature est stockée dans un fichier séparé (.sig)
  Les clés sont persistées sur disque (.pem)
=============================================================
  USAGE :
    # 1. Générer une paire de clés (une seule fois)
    python signature_numerique.py generer-cles --nom alice

    # 2. Signer un fichier
    python signature_numerique.py signer --fichier rapport.pdf --cle-privee alice_privee.pem

    # 3. Vérifier la signature
    python signature_numerique.py verifier --fichier rapport.pdf --signature rapport.pdf.sig --cle-publique alice_publique.pem

    # 4. Simulation complète (3 cas) sur un fichier
    python signature_numerique.py simuler --fichier rapport.pdf
=============================================================
"""

import argparse
import hashlib
import os
import shutil
import sys
import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed



# ─────────────────────────────────────────────
# Couleurs terminal
# ─────────────────────────────────────────────

VERT  = "\033[92m"
ROUGE = "\033[91m"
JAUNE = "\033[93m"
BLEU  = "\033[94m"
BOLD  = "\033[1m"
RESET = "\033[0m"

def titre(texte):
    print(f"\n{BLEU}{BOLD}{'='*62}{RESET}")
    print(f"{BLEU}{BOLD}  {texte}{RESET}")
    print(f"{BLEU}{BOLD}{'='*62}{RESET}")

def ok(texte):    print(f"  {VERT}✔  {texte}{RESET}")
def erreur(texte):print(f"  {ROUGE}✘  {texte}{RESET}")
def info(texte):  print(f"  {JAUNE}ℹ  {texte}{RESET}")
def sep():        print(f"  {'─'*56}")


# ─────────────────────────────────────────────
# Clés RSA
# ─────────────────────────────────────────────

def generer_paire_cles(taille_bits: int = 2048):
    cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=taille_bits)
    return cle_privee, cle_privee.public_key()


def sauvegarder_cles(cle_privee, nom: str):
    chemin_priv = Path(f"{nom}_privee.pem")
    chemin_pub  = Path(f"{nom}_publique.pem")
    chemin_priv.write_bytes(
        cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    chemin_pub.write_bytes(
        cle_privee.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return chemin_priv, chemin_pub


def charger_cle_privee(chemin: str):
    return serialization.load_pem_private_key(Path(chemin).read_bytes(), password=None)


def charger_cle_publique(chemin: str):
    return serialization.load_pem_public_key(Path(chemin).read_bytes())


# ─────────────────────────────────────────────
# Hash du fichier (lecture par blocs → gros fichiers OK)
# ─────────────────────────────────────────────

def hasher_fichier(chemin: str) -> bytes:
    """Calcule le SHA-256 d'un fichier quelconque, bloc par bloc."""
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        while bloc := f.read(65536):
            h.update(bloc)
    return h.digest()


# ─────────────────────────────────────────────
# Signature détachée
# ─────────────────────────────────────────────

def signer_fichier(chemin_fichier: str, cle_privee, chemin_sig: str = None) -> Path:
    """
    SIGNATURE DÉTACHÉE :
      - Hash SHA-256 du fichier calculé en mémoire
      - Signature RSA-PSS du hash
      - Résultat écrit dans <fichier>.sig (fichier original intact)
    """
    digest = hasher_fichier(chemin_fichier)
    signature = cle_privee.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        Prehashed(hashes.SHA256()),
    )
    chemin_sig = Path(chemin_sig or f"{chemin_fichier}.sig")
    chemin_sig.write_bytes(signature)
    return chemin_sig


def verifier_fichier(chemin_fichier: str, chemin_sig: str, cle_publique) -> bool:
    digest    = hasher_fichier(chemin_fichier)
    signature = Path(chemin_sig).read_bytes()
    try:
        cle_publique.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            Prehashed(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


# ─────────────────────────────────────────────
# Commandes CLI
# ─────────────────────────────────────────────

def cmd_generer_cles(args):
    titre(f"Génération des clés RSA-2048 pour « {args.nom} »")
    cle_privee, _ = generer_paire_cles()
    priv, pub = sauvegarder_cles(cle_privee, args.nom)
    ok(f"Clé privée   → {priv}  (gardez-la SECRÈTE)")
    ok(f"Clé publique → {pub}  (partagez-la librement)")


def cmd_signer(args):
    titre(f"Signature du fichier : {args.fichier}")
    if not Path(args.fichier).exists():
        erreur(f"Fichier introuvable : {args.fichier}"); sys.exit(1)

    cle_privee = charger_cle_privee(args.cle_privee)
    taille = Path(args.fichier).stat().st_size
    info(f"Fichier  : {args.fichier}  ({taille:,} octets)")
    digest = hasher_fichier(args.fichier)
    info(f"SHA-256  : {digest.hex()}")
    chemin_sig = signer_fichier(args.fichier, cle_privee)
    ok(f"Signature détachée écrite dans : {chemin_sig}")
    ok("Le fichier original N'A PAS été modifié.")
    info(f"Horodatage : {datetime.datetime.now().isoformat()}")


def cmd_verifier(args):
    titre(f"Vérification de la signature : {args.fichier}")
    for chemin in [args.fichier, args.signature, args.cle_publique]:
        if not Path(chemin).exists():
            erreur(f"Fichier introuvable : {chemin}"); sys.exit(1)

    cle_publique = charger_cle_publique(args.cle_publique)
    digest = hasher_fichier(args.fichier)
    info(f"Fichier    : {args.fichier}")
    info(f"SHA-256    : {digest.hex()}")
    info(f"Signature  : {args.signature}")
    info(f"Clé pub.   : {args.cle_publique}")
    sep()
    valide = verifier_fichier(args.fichier, args.signature, cle_publique)
    if valide:
        ok("Intégrité       : le fichier N'A PAS été altéré.")
        ok("Authenticité    : signature vérifiée avec succès.")
        ok("Non-répudiation : le signataire ne peut pas nier.")
    else:
        erreur("SIGNATURE INVALIDE")
        erreur("Intégrité       : VIOLATION — fichier ou signature altéré(e).")
        erreur("Authenticité    : REJETÉE.")


def cmd_simuler(args):
    """Simulation complète : 3 cas sur le fichier fourni en argument."""

    if not Path(args.fichier).exists():
        erreur(f"Fichier introuvable : {args.fichier}"); sys.exit(1)

    fichier_original = Path(args.fichier)
    taille = fichier_original.stat().st_size

    # ── Clés ────────────────────────────────
    titre("ÉTAPE 1 — Génération des clés RSA-2048")
    cle_privee_alice,   cle_pub_alice  = generer_paire_cles()
    cle_privee_mallory, cle_pub_mall   = generer_paire_cles()
    ok("Clé privée d'Alice   (SECRÈTE)")
    ok("Clé publique d'Alice (partagée)")
    ok("Clé de Mallory       (usurpatrice — simulation uniquement)")

    # ── Signature ───────────────────────────
    titre("ÉTAPE 2 — Alice signe le fichier (signature DÉTACHÉE)")
    info(f"Fichier : {fichier_original.name}  ({taille:,} octets)")
    digest = hasher_fichier(str(fichier_original))
    info(f"SHA-256 : {digest.hex()}")
    chemin_sig = Path(f"{fichier_original}.sig")
    signer_fichier(str(fichier_original), cle_privee_alice, str(chemin_sig))
    ok(f"Signature écrite dans : {chemin_sig.name}")
    ok("Fichier original INTACT (non modifié).")

    # ══════════════════════════════════════════
    # CAS 1 — FICHIER INTACT
    # ══════════════════════════════════════════
    titre("CAS 1 — Bob reçoit le fichier INTACT")
    valide = verifier_fichier(str(fichier_original), str(chemin_sig), cle_pub_alice)
    if valide:
        ok("Intégrité       : fichier non altéré ✔")
        ok("Authenticité    : signature d'Alice confirmée ✔")
        ok("Non-répudiation : Alice ne peut pas nier avoir signé ✔")
    else:
        erreur("Cas inattendu.")

    # ══════════════════════════════════════════
    # CAS 2 — FICHIER ALTÉRÉ (attaque MitM)
    # ══════════════════════════════════════════
    titre("CAS 2 — Attaque : un octet du fichier est modifié en transit")
    fichier_falsifie = Path(f"{fichier_original}.falsifie{fichier_original.suffix}")
    shutil.copy2(fichier_original, fichier_falsifie)
    with open(fichier_falsifie, "r+b") as f:
        milieu = max(0, taille // 2)
        f.seek(milieu)
        octet = f.read(1)
        f.seek(milieu)
        f.write(bytes([(octet[0] ^ 0xFF) if octet else 0xAB]))

    digest_falsifie = hasher_fichier(str(fichier_falsifie))
    info(f"SHA-256 original : {digest.hex()}")
    info(f"SHA-256 falsifié : {digest_falsifie.hex()}")
    info("→ Les hash diffèrent : altération détectée.")

    valide2 = verifier_fichier(str(fichier_falsifie), str(chemin_sig), cle_pub_alice)
    fichier_falsifie.unlink()
    if not valide2:
        erreur("Intégrité       : VIOLATION — modification détectée !")
        erreur("Authenticité    : REJETÉE   — signature invalide.")
        info ("Non-répudiation : N/A (message corrompu).")
    else:
        ok("Cas inattendu pour un fichier falsifié.")

    # ══════════════════════════════════════════
    # CAS 3 — USURPATION (Mallory signe à la place d'Alice)
    # ══════════════════════════════════════════
    titre("CAS 3 — Mallory signe le même fichier à la place d'Alice")
    chemin_sig_mallory = Path(f"{fichier_original}.mallory.sig")
    signer_fichier(str(fichier_original), cle_privee_mallory, str(chemin_sig_mallory))
    info("Mallory a produit sa propre signature sur le fichier.")
    info("Bob vérifie avec la clé publique d'ALICE.")
    valide3 = verifier_fichier(str(fichier_original), str(chemin_sig_mallory), cle_pub_alice)
    chemin_sig_mallory.unlink()
    if not valide3:
        erreur("Authenticité    : REJETÉE — signature étrangère détectée.")
        ok ("Non-répudiation : Alice protégée contre l'usurpation d'identité.")
    else:
        ok("Cas inattendu.")

    # ── Nettoyage & résumé ──────────────────
    chemin_sig.unlink(missing_ok=True)
    titre("RÉSUMÉ DE LA SIMULATION")
    print(f"""
  Fichier testé : {fichier_original.name}  ({taille:,} octets)
  Algorithme    : RSA-PSS 2048 bits + SHA-256 (signature détachée)

  ┌──────────────────┬─────────────────────────────────────┐
  │ Propriété        │ Résultats                            │
  ├──────────────────┼─────────────────────────────────────┤
  │ Intégrité        │ ✔ CAS 1 validé / ✘ CAS 2 rejeté     │
  │ Authenticité     │ ✔ CAS 1 validé / ✘ CAS 3 rejeté     │
  │ Non-répudiation  │ ✔ Alice ne peut pas nier sa signature│
  └──────────────────┴─────────────────────────────────────┘
""")


# ─────────────────────────────────────────────
# Point d'entrée
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Signature numérique détachée RSA-PSS + SHA-256",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python signature_numerique.py generer-cles --nom alice
  python signature_numerique.py signer    --fichier contrat.pdf --cle-privee alice_privee.pem
  python signature_numerique.py verifier  --fichier contrat.pdf --signature contrat.pdf.sig --cle-publique alice_publique.pem
  python signature_numerique.py simuler   --fichier image.png
        """,
    )
    sous = parser.add_subparsers(dest="commande", required=True)

    p1 = sous.add_parser("generer-cles", help="Génère une paire RSA et la sauvegarde en PEM")
    p1.add_argument("--nom", required=True, help="Préfixe (ex: alice → alice_privee.pem / alice_publique.pem)")

    p2 = sous.add_parser("signer", help="Signe un fichier → <fichier>.sig")
    p2.add_argument("--fichier",    required=True, help="Fichier à signer (PDF, image, ZIP…)")
    p2.add_argument("--cle-privee", required=True, help="Clé privée PEM du signataire")

    p3 = sous.add_parser("verifier", help="Vérifie la signature détachée")
    p3.add_argument("--fichier",      required=True, help="Fichier original")
    p3.add_argument("--signature",    required=True, help="Fichier .sig")
    p3.add_argument("--cle-publique", required=True, help="Clé publique PEM")

    p4 = sous.add_parser("simuler", help="Simulation complète (3 cas) sur un fichier fourni")
    p4.add_argument("--fichier", required=True, help="Fichier à utiliser pour la démonstration")

    args = parser.parse_args()
    {"generer-cles": cmd_generer_cles,
     "signer":       cmd_signer,
     "verifier":     cmd_verifier,
     "simuler":      cmd_simuler}[args.commande](args)


if __name__ == "__main__":
    main()