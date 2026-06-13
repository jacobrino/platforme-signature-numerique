from allauth.account.forms import ResetPasswordForm
from allauth.account.forms import LoginForm
from allauth.account.forms import SignupForm


class CustomResetPasswordForm(ResetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["email"].widget.attrs.update({
            "class": "form-control",
            "placeholder": "Votre adresse email",
        })

class CustomLoginForm(LoginForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Email / login field
        self.fields["login"].widget.attrs.update({
            "class": "form-control",
            "placeholder": "Votre email",
        })

        # Password field
        self.fields["password"].widget.attrs.update({
            "class": "form-control",
            "placeholder": "Votre mot de passe",
        })


class CustomSignupForm(SignupForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["email"].widget.attrs.update({
            "class": "form-control",
            "placeholder": "Votre email",
        })

        self.fields["password1"].widget.attrs.update({
            "class": "form-control",
            "placeholder": "Mot de passe",
        })

        self.fields["password2"].widget.attrs.update({
            "class": "form-control",
            "placeholder": "Confirmer mot de passe",
        })