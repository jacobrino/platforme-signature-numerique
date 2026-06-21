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
        print("PDFSIG OUTPUT:")
        print(output)
        # Aucune signature
        if "Signature #" not in output:
            result["error"] = (
                "Aucune signature numérique PDF trouvée."
            )
            return result
        # Signature détectée
        result["signature"]["exists"] = True
        # Nom du champ de signature
        field = re.search(
            r"Signature Field Name:\s*(.+)",
            output
        )
        if field:
            result["signature"]["field_name"] = (
                field.group(1).strip()
            )
        # Type signature
        sig_type = re.search(
            r"Signature Type:\s*(.+)",
            output
        )
        if sig_type:
            result["signature"]["type"] = (
                sig_type.group(1).strip()
            )

        # Algorithme de hachage
        algorithm = re.search(
            r"Signing Hash Algorithm:\s*(.+)",
            output
        )
        if algorithm:
            algo = algorithm.group(1).strip()
            # pdfsig peut retourner unknown
            if algo.lower() != "unknown":
                result["signature"]["algorithm"] = algo
        
        
        # Signataire
        subject = re.search(
            r"Signer full Distinguished Name:\s*(.+)",
            output
        )
        if subject:
            result["certificate"]["subject"] = (
                subject.group(1).strip()
            )
        # Date signature
        signing_time = re.search(
            r"Signing Time:\s*(.+)",
            output
        )
        if signing_time:
            result["signature"]["signing_time"] = (
                signing_time.group(1).strip()
            )
        # Vérification intégrité
        validation = re.search(
            r"Signature Validation:\s*(.+)",
            output
        )
        if validation:
            validation_result = (
                validation.group(1)
                .strip()
                .lower()
            )
            if "valid" in validation_result:
                result["signature"]["integrity"] = True
                result["status"] = "VALID"
            elif "unknown" in validation_result:
                # Signature présente mais certificat non reconnu
                result["signature"]["integrity"] = True
                result["status"] = "UNTRUSTED"
                result["error"] = (
                    "Signature présente mais validation "
                    "du certificat impossible."
                )
            else:
                result["status"] = "INVALID"
                result["error"] = (
                    "Signature PDF invalide."
                )
        else:
            # pdfsig peut ne pas donner validation complète
            if "Total document signed" in output:
                result["signature"]["integrity"] = True
                result["status"] = "UNTRUSTED"
                result["error"] = (
                    "Signature détectée mais validation "
                    "incomplète."
                )
        # Détection certificat auto-signé
        if (
            result["certificate"]["subject"]
            and
            "Issuer" in output
        ):
            issuer = re.search(
                r"Signer full Distinguished Name:\s*(.+)",
                output
            )
            if issuer and (
                issuer.group(1).strip()
                ==
                result["certificate"]["subject"]
            ):
                result["certificate"]["self_signed"] = True
        return result
    except subprocess.TimeoutExpired:
        result["error"] = (
            "Temps de vérification dépassé."
        )
        return result
    except Exception as e:
        result["error"] = str(e)
        return result