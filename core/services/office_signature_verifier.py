import zipfile
import re
from lxml import etree
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives import hashes

def verify_office_signature(file_path,name_file):
    result = {
        "status": "INVALID",
        "file_name":name_file,
        "signature": {
            "exists": False,
            "integrity": False,
            "algorithm": None,
            "signing_time": None
        },
        "certificate": {
            "subject": None,
            "issuer": None,
            "expiration": None,
            "fingerprint": None,
            "trusted": False,
            "self_signed": False
        },
        "error": None
    }
    try:
        with zipfile.ZipFile(file_path, "r") as office_file:
            files = office_file.namelist()
            signature_files = [
                f for f in files
                if f.startswith("_xmlsignatures/")
                and f.endswith(".xml")
            ]
            if not signature_files:
                result["error"] = (
                    "Aucune signature numérique trouvée."
                )
                return result
            result["signature"]["exists"] = True
            # Prendre le fichier signature XML
            signature_xml = office_file.read(
                signature_files[0]
            )
            root = etree.fromstring(signature_xml)
            # -----------------------------
            # Algorithme de signature
            # -----------------------------
            signature_method = root.xpath(
                "//*[local-name()='SignatureMethod']"
            )
            if signature_method:
                algorithm = signature_method[0].get(
                    "Algorithm"
                )
                result["signature"]["algorithm"] = algorithm.split("#")[-1]
            # -----------------------------
            # Date de signature
            # -----------------------------
            signing_time = root.xpath(
                "//*[local-name()='SigningTime']"
            )
            if signing_time:
                result["signature"]["signing_time"] = (
                    signing_time[0].text
                )
            # -----------------------------
            # Certificat X509
            # -----------------------------
            certificates = root.xpath(
                "//*[local-name()='X509Certificate']"
            )
            if certificates:
                certificate_base64 = (
                    certificates[0]
                    .text
                    .strip()
                )
                certificate = (
                    x509
                    .load_der_x509_certificate(
                        base64.b64decode(
                            certificate_base64
                        )
                    )
                )
                result["certificate"]["subject"] = (
                    certificate
                    .subject
                    .rfc4514_string()
                )
                result["certificate"]["issuer"] = (
                    certificate
                    .issuer
                    .rfc4514_string()
                )
                result["certificate"]["expiration"] = (
                    certificate
                    .not_valid_after
                    .isoformat()
                )
                result["certificate"]["fingerprint"] = (
                    certificate
                    .fingerprint(
                        hashes.SHA256()
                    )
                    .hex()
                )
                # certificat auto-signé ?
                if (
                    certificate.subject
                    ==
                    certificate.issuer
                ):
                    result["certificate"]["self_signed"] = True
            # -----------------------------
            # Vérification basique
            # -----------------------------
            #
            # Pour l'instant :
            # - signature XML trouvée
            # - certificat extrait
            #
            # La vérification XMLDSIG complète
            # sera ajoutée ensuite.
            #
            result["signature"]["integrity"] = True
            if result["certificate"]["self_signed"]:
                result["status"] = "UNTRUSTED"
                result["error"] = (
                    "Signature détectée mais "
                    "certificat auto-signé."
                )
            else:
                result["status"] = "UNTRUSTED"
                result["error"] = (
                    "Signature détectée. "
                    "La chaîne de confiance "
                    "du certificat doit être vérifiée."
                )
            return result
    except zipfile.BadZipFile:
        result["error"] = (
            "Le fichier Office est invalide."
        )
        return result
    except Exception as e:
        result["error"] = str(e)
        return result