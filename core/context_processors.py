from django.conf import settings

def site_name(request):
    # Remplacez 'MON_NOM_APP' par le nom exact de votre variable dans settings.py
    return {
        'SITE_NAME': getattr(settings, 'SITE_NAME', 'MonApp')
    }
