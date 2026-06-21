from django.shortcuts import render
from .services.file_validator import check_file_extension
from django.contrib import messages
from core.services.exe_signature_verifier import verify_exe_signature
from .services.office_signature_verifier import verify_office_signature
import tempfile
from .services.pdf_signature_verifier import verify_pdf_signature
# Create your views here.

def welcome_view(request):
    return render(request, "welcome.html")

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