import subprocess
import re

def verify_pdf_signature(file_path):
    """
    Vérification signature numérique PDF avec pdfsig.
    """
    result = {
        "status": "INVALID",
        "file": {
            "name": file_path
        },
        "signature": {
            "exists": False,
            "integrity": False,
            "signing_time": None,
            "field_name": None,
            "type": None,
            "algorithm": None,
        },
        "certificate": {
            "subject": None,
            "trusted": False,
            "self_signed": False
        },
        "error": None
    }
    try:
        process = subprocess.run(
            [
                "pdfsig",
                file_path
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = process.stdout + process.stderr
        print(output)

        if "Signature #" not in output:
            result["error"] = "Aucune signature numérique PDF trouvée."
            return result

        result["signature"]["exists"] = True

        field = re.search(
            r"Signature Field Name:\s*(.+)",
            output
        )
        if field:
            result["signature"]["field_name"] = field.group(1).strip()

        sig_type = re.search(
            r"Signature Type:\s*(.+)",
            output
        )
        if sig_type:
            result["signature"]["type"] = sig_type.group(1).strip()

        algorithm = re.search(
            r"Signing Hash Algorithm:\s*(.+)",
            output
        )
        if algorithm:
            algo = algorithm.group(1).strip()
            if algo.lower() != "unknown":
                result["signature"]["algorithm"] = algo

        subject = re.search(
            r"Signer full Distinguished Name:\s*(.+)",
            output
        )
        if subject:
            result["certificate"]["subject"] = subject.group(1).strip()

        signing_time = re.search(
            r"Signing Time:\s*(.+)",
            output
        )
        if signing_time:
            result["signature"]["signing_time"] = signing_time.group(1).strip()

        signature_validation = re.search(
            r"Signature Validation:\s*(.+)",
            output
        )
        if signature_validation:
            validation = signature_validation.group(1).strip().lower()

            if "valid" in validation:
                result["signature"]["integrity"] = True
            else:
                result["error"] = "Signature PDF invalide."
                return result

        certificate_validation = re.search(
            r"Certificate Validation:\s*(.+)",
            output
        )
        if certificate_validation:
            cert_status = certificate_validation.group(1).strip().lower()

            if "valid" in cert_status:
                result["certificate"]["trusted"] = True
            elif "unknown" in cert_status:
                result["error"] = (
                    "Signature valide mais certificat non reconnu ou non approuvé."
                )

        if result["signature"]["integrity"]:
            if result["certificate"]["trusted"]:
                result["status"] = "VALID"
            else:
                result["status"] = "UNTRUSTED"

        issuer = re.search(
            r"Issuer:\s*(.+)",
            output
        )
        if (
            issuer
            and result["certificate"]["subject"]
            and issuer.group(1).strip() == result["certificate"]["subject"]
        ):
            result["certificate"]["self_signed"] = True

        return result

    except subprocess.TimeoutExpired:
        result["error"] = "Temps de vérification dépassé."
        return result

    except Exception as e:
        result["error"] = str(e)
        return result