import subprocess
import os
import re
from django.conf import settings


def sign_file(file_path):
    cert = str(settings.CMS_CERTIFICATE)
    key = str(settings.CMS_PRIVATE_KEY)
    sig_path = file_path + ".sig"

    print("=== SIGNATURE CMS ===")
    print("Fichier :", file_path)
    print("Certificat :", cert)
    print("Clé :", key)

    cmd = [
        "openssl", "cms", "-sign",
        "-binary",
        "-in", file_path,
        "-signer", cert,
        "-inkey", key,
        "-out", sig_path,
        "-outform", "DER",
        "-nodetach"
    ]

    print("Commande :", " ".join(cmd))

    try:
        p = subprocess.run(cmd, capture_output=True, text=True)

        print("STDOUT :", p.stdout)
        print("STDERR :", p.stderr)

        if p.returncode == 0:
            print("Signature créée :", sig_path)
            print("Taille :", os.path.getsize(sig_path), "octets")
            return sig_path

        print("Erreur signature")
        return None

    except Exception as e:
        print("Exception :", e)
        return None



def verify_file_signature(file_path, sig_path):
    print("=== VERIFICATION CMS ===")
    print("Fichier :", file_path)
    print("Signature :", sig_path)

    result = {
        "status": "INVALID",
        "signature": {
            "exists": False,
            "integrity": False
        },
        "certificate": {
            "subject": None,
            "issuer": None,
            "self_signed": False
        },
        "error": None
    }

    try:
        cmd = [
            "openssl", "cms",
            "-verify",
            "-binary",
            "-in", sig_path,
            "-inform", "DER",
            "-content", file_path,
            "-noverify"
        ]

        p = subprocess.run(cmd, capture_output=True, text=True)

        output = p.stdout + p.stderr

        print(output)

        result["signature"]["exists"] = True

        if p.returncode == 0:
            result["status"] = "VALID"
            result["signature"]["integrity"] = True
        else:
            result["error"] = output


        cert_cmd = [
            "openssl",
            "pkcs7",
            "-inform", "DER",
            "-in", sig_path,
            "-print_certs",
            "-noout"
        ]

        cert = subprocess.run(
            cert_cmd,
            capture_output=True,
            text=True
        ).stdout

        print("CERTIFICAT :")
        print(cert)

        subject = re.search(r"subject=(.+)", cert)
        issuer = re.search(r"issuer=(.+)", cert)

        if subject:
            result["certificate"]["subject"] = subject.group(1).strip()

        if issuer:
            result["certificate"]["issuer"] = issuer.group(1).strip()

        if (
            result["certificate"]["subject"]
            ==
            result["certificate"]["issuer"]
        ):
            result["certificate"]["self_signed"] = True

        print("RESULTAT :", result)

        return result

    except Exception as e:
        result["error"] = str(e)
        print("Exception :", e)
        return result