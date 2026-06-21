from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".msi",
    ".cab",
    ".cat",

    ".docx",
    ".xlsx",
    ".pptx",
    
    ".pdf"

    # ".dll",
    # ".sys",
    # ".pdf",
    # ".png",
    # ".docx",
}


def check_file_extension(filename):
    """
    Vérifie si l'extension du fichier est supportée.
    """

    extension = Path(filename).suffix.lower()

    if extension not in SUPPORTED_EXTENSIONS:
        return {
            "supported": False,
            "message": "Fichier non géré (en cours de développement)."
        }

    return {
        "supported": True,
        "extension": extension
    }