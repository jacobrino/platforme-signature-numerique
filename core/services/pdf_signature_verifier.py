from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import SignatureStatus

from cryptography import x509

def verify_pdf_signature(file_path):
    result = {
        "status": "INVALID",
        "file": {
            "name": file_path
        },
        "signature": {
            "exists": False,
            "integrity": False,
            "signing_time": None,
            "field_name": None
        },
        "certificate": {
            "subject": None,
            "issuer": None,
            "expiration": None,
            "trusted": False,
            "self_signed": False
        },
        "error": None
    }
    try:
        with open(file_path, "rb") as doc:
            reader = PdfFileReader(doc)
            signatures = (
                reader.embedded_signatures
            )
            if not signatures:
                result["error"] = (
                    "Aucune signature PDF trouvée."
                )
                return result
            # Première signature
            sig = signatures[0]
            result["signature"]["exists"] = True
            result["signature"]["field_name"] = (
                sig.field_name
            )
            status = validate_pdf_signature(
                sig
            )
            if status.bottom_line:
                result["signature"]["integrity"] = True
                result["status"] = "VALID"
            else:
                result["status"] = "INVALID"
            # Certificat
            if sig.signer_cert:
                cert = sig.signer_cert
                result["certificate"]["subject"] = (
                    cert.subject.rfc4514_string()
                )
                result["certificate"]["issuer"] = (
                    cert.issuer.rfc4514_string()
                )
                result["certificate"]["expiration"] = (
                    cert.not_valid_after.isoformat()
                )
                if cert.subject == cert.issuer:

                    result["certificate"]["self_signed"] = True
            if result["certificate"]["self_signed"]:
                result["status"] = "UNTRUSTED"
                result["error"] = (
                    "Signature PDF valide mais "
                    "certificat auto-signé."
                )
            return result
    except Exception as e:
        result["error"] = str(e)
        return result