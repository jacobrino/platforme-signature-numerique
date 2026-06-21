"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.shortcuts import render
from core.views import welcome_view
from django.contrib.auth.decorators import login_required
from core.views import verify_file

@login_required
def test_view(request):
    return render(request, "test.html")


urlpatterns = [
    path('admin/', admin.site.urls),

    # path('', include('allauth.urls')),
    # path('auth/', include('allauth.urls')),
    path('accounts/', include('allauth.urls')),


    # path('', RedirectView.as_view(url='account/login/', permanent=False), name='index'),

    #Importer les authentifications view et controller.

    # login propre
    # path('login/', RedirectView.as_view(url='/auth/login/')),
    # path('register/', RedirectView.as_view(url='/auth/signup/')),
    # path('logout/', RedirectView.as_view(url='/auth/logout/')),

    # path('auth/', include('allauth.urls')),

    path('test/', test_view, name='test'),
    path('i18n/', include('django.conf.urls.i18n')), #Pour faire fonctionner la langue


    path('verify/', verify_file, name='verify'),

    path('', welcome_view, name='welcome'),




]

