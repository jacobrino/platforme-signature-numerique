```markdown
# 🔐 Plateforme de Simulation de Signature Numérique

Une plateforme web développée avec **Django** permettant de **simuler le fonctionnement d'une signature numérique** à travers la génération, la signature et la vérification de fichiers. Ce projet a été conçu dans un objectif pédagogique afin de comprendre les principes de la cryptographie asymétrique et de l'intégrité des documents.

## 📖 Description

Cette plateforme est une solution de signature électronique moderne conçue pour simplifier, sécuriser et automatiser le processus de signature et de gestion de vos documents. Que ce soit pour des contrats, des accords ou des formalités administratives, elle offre un flux de travail fluide et totalement dématérialisé.

Dans le cadre de ce projet, la plateforme met l'accent sur la **simulation d'une signature numérique**, permettant aux utilisateurs de :

- Générer une paire de clés cryptographiques.
- Signer un document.
- Produire une **signature détachée** (`.sig`).
- Vérifier l'authenticité et l'intégrité d'un document à partir de sa signature.
- Comprendre les différentes étapes du processus de signature numérique.

---

## ✨ Fonctionnalités

- 🔑 Authentification sécurisée des utilisateurs avec **Django Allauth**
- 👤 Gestion des comptes utilisateurs
- 📄 Téléversement de documents
- ✍️ Signature numérique des fichiers
- 📎 Génération de signatures détachées (`.sig`)
- ✅ Vérification des signatures numériques
- 🔒 Contrôle de l'intégrité des documents
- 📊 Interface responsive réalisée avec **Bootstrap**

---

## 🛠️ Technologies utilisées

- **Backend**
  - Django
  - Python

- **Frontend**
  - HTML5
  - CSS3
  - Bootstrap
  - JavaScript

- **Authentification**
  - Django Allauth

- **Base de données**
  - Mysql

- **Cryptographie**
  - Signature numérique
  - Fonction de hachage
  - Clés publique / privée
  - Signature détachée (`.sig`)

---


---

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-utilisateur/votre-projet.git
cd votre-projet
````

### 2. Créer un environnement virtuel

```bash
python -m venv venv
```

### 3. Activer l'environnement

**Windows**

```bash
venv\Scripts\activate
```

**Linux / macOS**

```bash
source venv/bin/activate
```

### 4. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 5. Effectuer les migrations

```bash
python manage.py migrate
```

### 6. Créer un superutilisateur

```bash
python manage.py createsuperuser
```

### 7. Lancer le serveur

```bash
python manage.py runserver
```

Puis ouvrir :

```
http://127.0.0.1:8000/
```

---

## 🔐 Processus de signature

1. L'utilisateur charge un document.
2. Le système calcule son empreinte (hash).
3. Cette empreinte est signée avec la clé privée.
4. Une signature détachée (`.sig`) est générée.
5. Lors de la vérification :

   * le hash du document est recalculé ;
   * la signature est vérifiée à l'aide de la clé publique ;
   * les deux empreintes sont comparées afin de confirmer l'intégrité et l'authenticité du document.

---

## 📎 Signature détachée

La plateforme utilise une **signature détachée**.

Le document original n'est jamais modifié. La signature est enregistrée dans un fichier indépendant portant l'extension :

```
.sig
```

La vérification nécessite donc :

* le document original ;
* le fichier `.sig` correspondant.

---

## 🎯 Objectif pédagogique

Ce projet a pour objectif de démontrer le fonctionnement d'une signature numérique et de sensibiliser aux concepts suivants :

* cryptographie asymétrique ;
* intégrité des données ;
* authentification ;
* non-répudiation ;
* gestion des certificats et des signatures numériques.



## 👨‍💻 Auteur

**Jacob Rino Andrianjara & RAFANOMEZANTSOA Crescent Berthieu Victorien & TSIRESILAZA Deraniaina Noël **

Projet académique pour Master en Objets Connectés et Cybersécurités à l'ENI

---


Vous êtes libre de l'utiliser, de le modifier et de le distribuer conformément aux termes de cette licence.

```
```
