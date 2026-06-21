import subprocess
import re


def verify_exe_signature(file_path):
    """
    Vérifie une signature Authenticode avec osslsigncode.
    Retourne un résultat exploitable par Django.
    """
    try:
        process = subprocess.run(
            [
                "osslsigncode",
                "verify",
                file_path
            ],
            capture_output=True,
            text=True,
            timeout=30
        )
        output = process.stdout + process.stderr
        print("OUTPUT COMPLET:")
        print(output)

        result = {
            "file_name":"",
            "status": "INVALID",
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
                "trusted": False,
                "self_signed": False
            },
            "error": None
        }
        
        result["file_name"]=file_path

        # Algorithme
        algo = re.search(
            r"Message digest algorithm\s*:\s*(\w+)",
            output
        )
        if algo:
            result["signature"]["algorithm"] = algo.group(1)
        print("Algo : ",algo)
        print("Algo result: ",result)
        # Signataire
        signer = re.search(
            r"Subject:\s*(.+)",
            output
        )
        if signer:
            subject = signer.group(1).strip()
            result["certificate"]["subject"] = subject
        print("Signer : ",signer)
        print("Signer result: ",result)

        # Expiration certificat
        expiration = re.search(
            r"notAfter\s*:\s*(.+)",
            output
        )
        if expiration:
            result["certificate"]["expiration"] = expiration.group(1).strip()
        print("expiration : ",expiration)
        print("expiration result: ",result)

        # Date signature
        signing_time = re.search(
            r"Signing time:\s*(.+)",
            output
        )
        # Date d'horodatage Authenticode
        timestamp_time = re.search(
            r"Timestamp time:\s*(.+)",
            output
        )
        if signing_time:
            result["signature"]["signing_time"] = (
                signing_time.group(1).strip()
            )
        elif timestamp_time:
            result["signature"]["signing_time"] = (
                timestamp_time.group(1).strip()
            )
        print("signing_time : ",signing_time)
        print("signing_time result: ",result)

        # Vérification finale
        # if "Number of verified signatures: 1" in output:
        #     result["signature"]["exists"] = True
        #     if "Current message digest" in output:
        #         result["signature"]["integrity"] = True
        #     if "self-signed certificate" in output:
        #         result["status"] = "UNTRUSTED"
        #         result["certificate"]["self_signed"] = True
        #         result["error"] = (
        #             "Signature valide mais certificat auto-signé."
        #         )
        #     elif "Signature verification: failed" not in output:
        #         result["status"] = "VALID"
        #         result["certificate"]["trusted"] = True
        # if not result["valid"]:
        #     if "self-signed certificate" in output:
        #         result["error"] = (
        #             "Signature détectée mais certificat non reconnu "
        #             "(certificat auto-signé)."
        #         )
        #     else:
        #         result["error"] = (
        #             "Signature invalide ou fichier modifié."
        #         )

        if "Number of verified signatures: 1" in output:
            # Une signature existe
            result["signature"]["exists"] = True
            # Vérification intégrité réelle
            current_digest = re.search(
                r"Current message digest\s+:\s+([A-F0-9]+)",
                output
            )
            calculated_digest = re.search(
                r"Calculated message digest\s+:\s+([A-F0-9]+)",
                output
            )
            if current_digest and calculated_digest:
                current = current_digest.group(1).strip()
                calculated = calculated_digest.group(1).strip()
                print("HASH SIGNE :", current)
                print("HASH CALCULE :", calculated)
                if current == calculated:
                    print("ici signature integrity is TRUE")
                    result["signature"]["integrity"] = True
            # Certificat auto-signé
            if "self-signed certificate" in output:
                result["status"] = "UNTRUSTED"
                result["certificate"]["self_signed"] = True
                result["error"] = (
                    "Signature valide mais certificat auto-signé."
                )

            # Certificat intermédiaire/racine absent
            elif "unable to get local issuer certificate" in output:
                print("ICI elif untrusted")
                result["status"] = "UNTRUSTED"
                result["error"] = (
                    "Signature valide mais chaîne de certification "
                    "non vérifiée."
                )
            # Tout est valide
            elif result["signature"]["integrity"]:
                print("ICI elif tout est valide")
                result["status"] = "VALID"
                result["certificate"]["trusted"] = True
            
        else:
            result["status"] = "INVALID"
            result["error"] = (
                "Aucune signature trouvée."
            )
        
        print('Result final: ',result)
        return result
    except subprocess.TimeoutExpired:
        print('Timeout expired: ',e)
        return {
            "valid": False,
            "error": "Temps de vérification dépassé."
        }
    except Exception as e:
        print('Exception: ',e)
        return {
            "valid": False,
            "error": str(e)
        }


# jacob@jacob-IdeaPad-3-15IAU7:~/sign_exe$ osslsigncode verify mon_programme_signe.exe
# PE checksum   : 0004AFCC


# Signature Index: 0  (Primary Signature)

# Message digest algorithm  : SHA256
# Current message digest    : 80CDF834C2DB3EAC3C751176838FBADE40E788726722619BF43329DAFB44B75E 
# Calculated message digest : 80CDF834C2DB3EAC3C751176838FBADE40E788726722619BF43329DAFB44B75E 

# Signer's certificate:
# 	------------------
# 	Signer #0:
# 		Subject: /CN=Jacob/O=JCT/C=FR
# 		Issuer : /CN=Jacob/O=JCT/C=FR
# 		Serial : 055D5F1A3DF4E311C9F4DBEB07A56301F2A6028C
# 		Certificate expiration date:
# 			notBefore : Jun  9 12:45:30 2026 GMT
# 			notAfter : Jun  9 12:45:30 2027 GMT

# Message digest algorithm: SHA256

# Authenticated attributes:
# 	Signing time: Jun  9 12:56:29 2026 GMT
# 	Microsoft Individual Code Signing purpose
# 	URL description: https://jct.mg
# 	Text description: JCT App
# 	Message digest: FA0BEF980E1860D50556AA00109BB4F7FA1144B02EFDFBD6DA3C4061111AF523 

# Countersignatures:
# 	Timestamp time: Jun  9 12:56:30 2026 GMT
# 	Signing time: Jun  9 12:56:30 2026 GMT
# 	Hash Algorithm: sha256
# 	Issuer: /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
# 	Serial: 0A80EF184B8DF10582D1C476A7957468

# CAfile: /etc/ssl/certs/ca-certificates.crt
# TSA's certificates file: /etc/ssl/certs/ca-certificates.crt

# Timestamp verified using:
# 	------------------
# 	Signer #2:
# 		Subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Serial : 059B1B579E8E2132E23907BDA777755C
# 		Certificate expiration date:
# 			notBefore : Aug  1 12:00:00 2013 GMT
# 			notAfter : Jan 15 12:00:00 2038 GMT

# 	------------------
# 	Signer #1:
# 		Subject: /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
# 		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Serial : 0DC7AC5705FF21992E4043220C3A4986
# 		Certificate expiration date:
# 			notBefore : May  7 00:00:00 2025 GMT
# 			notAfter : Jan 14 23:59:59 2038 GMT

# 	------------------
# 	Signer #0:
# 		Subject: /C=US/O=DigiCert, Inc./CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1
# 		Issuer : /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
# 		Serial : 0A80EF184B8DF10582D1C476A7957468
# 		Certificate expiration date:
# 			notBefore : Jun  4 00:00:00 2025 GMT
# 			notAfter : Sep  3 23:59:59 2036 GMT

# TSA's CRL distribution point: http://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl
# Connecting to http://crl3.digicert.com/DigiCertTrustedG4TimeStampingRSA4096SHA2562025CA1.crl

# Certificate Revocation List verified using:
# 	------------------
# 	Signer #2:
# 		Subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Serial : 059B1B579E8E2132E23907BDA777755C
# 		Certificate expiration date:
# 			notBefore : Aug  1 12:00:00 2013 GMT
# 			notAfter : Jan 15 12:00:00 2038 GMT

# 	------------------
# 	Signer #1:
# 		Subject: /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
# 		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Serial : 0DC7AC5705FF21992E4043220C3A4986
# 		Certificate expiration date:
# 			notBefore : May  7 00:00:00 2025 GMT
# 			notAfter : Jan 14 23:59:59 2038 GMT

# 	------------------
# 	Signer #0:
# 		Subject: /C=US/O=DigiCert, Inc./CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1
# 		Issuer : /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
# 		Serial : 0A80EF184B8DF10582D1C476A7957468
# 		Certificate expiration date:
# 			notBefore : Jun  4 00:00:00 2025 GMT
# 			notAfter : Sep  3 23:59:59 2036 GMT

# Timestamp Server Signature CRL verification: ok
# Timestamp Server Signature verification: ok
# Signature verification time: Jun  9 12:56:30 2026 GMT
# Signing certificate chain verified using:
# 	------------------
# 	Signer #0:
# 		Subject: /CN=Jacob/O=JCT/C=FR
# 		Issuer : /CN=Jacob/O=JCT/C=FR
# 		Serial : 055D5F1A3DF4E311C9F4DBEB07A56301F2A6028C
# 		Certificate expiration date:
# 			notBefore : Jun  9 12:45:30 2026 GMT
# 			notAfter : Jun  9 12:45:30 2027 GMT

# 	Error: self-signed certificate

# PKCS7_verify error

# Failed signing certificate chain retrieved from the signature:
# 	------------------
# 	Signer #0:
# 		Subject: /CN=Jacob/O=JCT/C=FR
# 		Issuer : /CN=Jacob/O=JCT/C=FR
# 		Serial : 055D5F1A3DF4E311C9F4DBEB07A56301F2A6028C
# 		Certificate expiration date:
# 			notBefore : Jun  9 12:45:30 2026 GMT
# 			notAfter : Jun  9 12:45:30 2027 GMT

# 	------------------
# 	Signer #1:
# 		Subject: /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Assured ID Root CA
# 		Serial : 0E9B188EF9D02DE7EFDB50E20840185A
# 		Certificate expiration date:
# 			notBefore : Aug  1 00:00:00 2022 GMT
# 			notAfter : Nov  9 23:59:59 2031 GMT

# 	------------------
# 	Signer #2:
# 		Subject: /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
# 		Issuer : /C=US/O=DigiCert Inc/OU=www.digicert.com/CN=DigiCert Trusted Root G4
# 		Serial : 0DC7AC5705FF21992E4043220C3A4986
# 		Certificate expiration date:
# 			notBefore : May  7 00:00:00 2025 GMT
# 			notAfter : Jan 14 23:59:59 2038 GMT

# 	------------------
# 	Signer #3:
# 		Subject: /C=US/O=DigiCert, Inc./CN=DigiCert SHA256 RSA4096 Timestamp Responder 2025 1
# 		Issuer : /C=US/O=DigiCert, Inc./CN=DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1
# 		Serial : 0A80EF184B8DF10582D1C476A7957468
# 		Certificate expiration date:
# 			notBefore : Jun  4 00:00:00 2025 GMT
# 			notAfter : Sep  3 23:59:59 2036 GMT

# 40B9ECB81E760000:error:10800075:PKCS7 routines:PKCS7_verify:certificate verify error:../crypto/pkcs7/pk7_smime.c:296:Verify error: self-signed certificate
# Signature verification: failed

# Number of verified signatures: 1
# Failed
