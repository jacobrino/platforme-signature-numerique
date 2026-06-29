# 🔐 Plateforme de Simulation de Signature Numérique

Application web développée avec **Django** permettant de simuler le fonctionnement d'une **signature numérique** : génération de clés, signature de documents et vérification d'intégrité.

Ce projet a été réalisé dans un objectif pédagogique afin de comprendre les principes de la **cryptographie asymétrique** et de la protection des documents numériques.

---

## 📖 Description

La plateforme permet aux utilisateurs de :

* Générer une paire de clés cryptographiques (publique et privée).
* Importer un document.
* Signer un fichier avec une clé privée.
* Générer une signature détachée (`.sig`).
* Vérifier l'authenticité et l'intégrité d'un document.

Le document original reste inchangé, la signature étant stockée séparément.

---

## ✨ Fonctionnalités

* 🔑 Authentification des utilisateurs avec Django Allauth
* 👤 Gestion des comptes utilisateurs
* 📄 Téléversement de documents
* ✍️ Signature numérique des fichiers
* 📎 Génération de fichiers `.sig`
* ✅ Vérification des signatures
* 🔒 Contrôle de l'intégrité des données
* 📱 Interface responsive avec Bootstrap

---

## 🛠️ Technologies utilisées

### Backend

* Django
* Python

### Frontend

* HTML5
* CSS3
* Bootstrap
* JavaScript

### Base de données

* MySQL

### Cryptographie

* Cryptographie asymétrique
* Fonction de hachage
* Clé publique / clé privée
* Signature détachée (`.sig`)

---

## 🚀 Installation

### 1. Cloner le projet

```bash
git clone https://github.com/votre-utilisateur/votre-projet.git
cd votre-projet
```

### 2. Créer un environnement virtuel

```bash
python -m venv venv
```

### 3. Activer l'environnement

Windows :

```bash
venv\Scripts\activate
```

Linux / macOS :

```bash
source venv/bin/activate
```

### 4. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 5. Appliquer les migrations

```bash
python manage.py migrate
```

### 6. Créer un administrateur

```bash
python manage.py createsuperuser
```

### 7. Démarrer le serveur

```bash
python manage.py runserver
```

Accéder à l'application :

```
http://127.0.0.1:8000/
```

---

## 🔐 Fonctionnement de la signature numérique

1. L'utilisateur sélectionne un document.
2. Le système calcule son empreinte numérique (hash).
3. L'empreinte est signée avec la clé privée.
4. Un fichier de signature `.sig` est généré.
5. Lors de la vérification :

   * le hash du document est recalculé ;
   * la signature est vérifiée avec la clé publique ;
   * l'intégrité et l'authenticité du document sont confirmées.

---

## 🎯 Objectif pédagogique

Ce projet permet de comprendre :

* La cryptographie asymétrique.
* L'intégrité des données.
* L'authentification numérique.
* La non-répudiation.
* Le fonctionnement d'une signature numérique.

---

## 👨‍💻 Auteurs

**Jacob Rino Andrianjara**
**RAFanomezantsoa Crescent Berthieu Victorien**
**TSIRESILAZA Deraniaina Noël**

Projet académique réalisé dans le cadre du **Master Objets Connectés et Cybersécurité** à l'**École Nationale d'Informatique (ENI)**.
