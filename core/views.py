from django.shortcuts import render
from .services.file_validator import check_file_extension
from django.contrib import messages
from core.services.exe_signature_verifier import verify_exe_signature
from .services.office_signature_verifier import verify_office_signature
import tempfile
from .services.pdf_signature_verifier import verify_pdf_signature
from django.core.files.storage import default_storage

from core.services.cms_signature_service import (
    sign_file,
    verify_file_signature
)


# Create your views here.

def welcome_view(request):
    return render(request, "welcome.html")



def sign_view(request):
    result = None
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]

        path = default_storage.save(
            uploaded_file.name,
            uploaded_file
        )
        file_path = default_storage.path(path)
        print("Fichier à signer :", file_path)
        signature_path = sign_file(file_path)
        if signature_path:
            result = {
                "status": "SUCCESS",
                "message": "Signature numérique créée.",
                "signature_file": signature_path
            }
        else:
            result = {
                "status": "ERROR",
                "message": "Erreur lors de la création de la signature."
            }
        print("Résultat :", result)
        if signature_path:
            result = {
                "status": "SUCCESS",
                "message": "Signature créée avec succès.",
                "signature_file": signature_path
            }
        else:
            result = {
                "status": "ERROR",
                "message": "Impossible de créer la signature numérique."
            }
    return render(
        request,
        "cms/sign.html",
        {
            "result": result
        }
    )

def verify_file(request):
    result = None

    if request.method == "POST":
        uploaded_file = request.FILES.get("file")
        print("uploaded_file: ",uploaded_file,uploaded_file.name)
        if uploaded_file:
            extension_result = check_file_extension(
                uploaded_file.name
            )
            if not extension_result["supported"]:

                messages.warning(
                    request,
                    extension_result["message"]
                )
                return render(request, "verify.html")
            
            if extension_result["extension"] in [".exe",".dll",".sys",".msi",".cab",".cat",]:
                # sauvegarde temporaire
                with open(
                    uploaded_file.name,
                    "wb+"
                ) as destination:

                    for chunk in uploaded_file.chunks():
                        destination.write(chunk)
                
                print("Result après chunk",result,uploaded_file.name)

                result = verify_exe_signature(uploaded_file.name)
                if result["status"] == "VALID":
                    messages.success(
                        request,
                        "Signature valide et certificat reconnu."
                    )
                elif result["status"] == "UNTRUSTED":
                    messages.warning(
                        request,
                        "Signature détectée mais certificat non approuvé."
                    )
                else:
                    messages.error(
                        request,
                        "Signature invalide ou fichier modifié."
                    )
            elif extension_result["extension"] in [
                ".docx",
                ".xlsx",
                ".pptx"
            ]:
                with tempfile.NamedTemporaryFile(
                    delete=False
                ) as temp_file:
                    for chunk in uploaded_file.chunks():
                        temp_file.write(chunk)
                    temp_path = temp_file.name
                result = verify_office_signature(
                    temp_path,uploaded_file.name
                )
                messages.success(
                    request,
                    "Analyse du document Office terminée."
                )
            elif extension_result["extension"] == ".pdf":
                with tempfile.NamedTemporaryFile(
                    delete=False
                ) as temp_file:
                    for chunk in uploaded_file.chunks():
                        temp_file.write(chunk)
                    temp_path = temp_file.name
                result = verify_pdf_signature(
                    temp_path
                )
                messages.success(
                    request,
                    "Analyse PDF terminée."
                )

    return render(request,"verify.html",{
        "verification_result": result
    }
    )

def cms_sign_view(request):
    result = None
    if request.method == "POST" and request.FILES.get("file"):
        uploaded = request.FILES["file"]
        path = default_storage.save(
            uploaded.name,
            uploaded
        )
        file_path = default_storage.path(path)
        print("Fichier reçu :", file_path)
        sig_path = sign_file(file_path)
        if sig_path:
            result = {
                "status": "SUCCESS",
                "message": "Signature créée",
                "signature": sig_path
            }
        else:
            result = {
                "status": "ERROR",
                "message": "Erreur création signature"
            }
    return render(
        request,
        "cms/sign.html",
        {
            "result": result
        }
    )
def cms_verify_view(request):
    verification_result = None
    if (
        request.method == "POST"
        and request.FILES.get("file")
        and request.FILES.get("signature")
    ):
        file = request.FILES["file"]
        sig = request.FILES["signature"]
        file_path = default_storage.save(
            file.name,
            file
        )
        sig_path = default_storage.save(
            sig.name,
            sig
        )
        file_path = default_storage.path(file_path)
        sig_path = default_storage.path(sig_path)
        print("Fichier :", file_path)
        print("Signature :", sig_path)
        verification_result = verify_file_signature(
            file_path,
            sig_path
        )
    return render(
        request,
        "cms/verify.html",
        {
            "verification_result": verification_result
        }
    )