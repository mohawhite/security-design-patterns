# Application Web Sécurisée - Design Patterns de Sécurité

**Auteur:** Amir Moussi

## Description

Application web développée en Node.js avec Express implémentant les 4 Design Patterns de sécurité:
- **Authentication Enforcer** - Authentification centralisée avec bcrypt
- **Authorization RBAC** - Contrôle d'accès basé sur les rôles
- **Input Validation** - Validation et détection d'injections
- **Security Audit Logging** - Journalisation complète des événements

---

## Installation

### Option 1: Installation Standard

#### Prérequis
- Node.js 14+
- npm

#### Étapes

```bash
cd security_app
npm install
```

#### Configuration

**Important:** L'application fonctionne sans configuration avec les valeurs par défaut.

Pour personnaliser les identifiants, créez un fichier `.env` à partir du template:

```bash
cp .env.example .env
```

Puis éditez `.env` avec vos propres valeurs. Si le fichier `.env` n'existe pas, l'application utilisera les valeurs par défaut listées ci-dessous.

#### Démarrage

```bash
npm start
```

Application accessible sur: **http://localhost:3000**

---

### Option 2: Installation avec Docker

#### Prérequis
- Docker
- Docker Compose

#### Démarrage rapide

```bash
cd security_app

# Créer le fichier .env (optionnel)
cp .env.example .env

# Construire et démarrer le conteneur
docker-compose up -d

# Voir les logs
docker-compose logs -f
```

Application accessible sur: **http://localhost:3000**

#### Commandes Docker utiles

```bash
# Arrêter l'application
docker-compose down

# Reconstruire après modifications
docker-compose up -d --build

# Supprimer tout (conteneurs + volumes)
docker-compose down -v
```

#### Avantages Docker
- Environnement isolé et reproductible
- Pas besoin d'installer Node.js localement
- Persistance des données (logs et base de données)
- Déploiement simplifié

---

### Comptes de test (par défaut)

| Utilisateur | Mot de passe | Rôle   | Permissions            |
|-------------|--------------|--------|------------------------|
| admin       | Admin@123    | admin  | read, write, delete, admin |
| editor      | Editor@123   | editor | read, write            |
| viewer      | Viewer@123   | viewer | read                   |

**Note:** Les identifiants peuvent être modifiés dans le fichier `.env`

---

## Structure du Projet

```
security_app/
├── app.js                    # Application Express principale
├── package.json              # Dépendances Node.js
├── .env                      # Variables d'environnement (gitignored)
├── .env.example              # Template de configuration
├── Dockerfile                # Configuration Docker
├── docker-compose.yml        # Orchestration Docker
├── .dockerignore             # Fichiers exclus de Docker
├── database.sqlite           # Base de données SQLite
├── security/
│   ├── authentication.js     # Authentication Enforcer
│   ├── authorization.js      # Authorization RBAC
│   ├── validation.js         # Input Validation
│   ├── audit.js              # Security Audit Logging
│   └── database.js           # Gestion base de données
├── templates/
│   ├── login.html            # Page de connexion
│   ├── register.html         # Page d'inscription
│   ├── dashboard.html        # Dashboard utilisateur
│   ├── profile.html          # Page de profil utilisateur
│   ├── admin.html            # Panneau d'administration
│   ├── 404.html              # Page erreur 404
│   ├── 403.html              # Page erreur 403
│   └── 500.html              # Page erreur 500
├── tests/
│   ├── security-tests.js     # Tests de sécurité automatisés
│   └── test-results.json     # Résultats des tests
├── logs/
│   └── security_audit.log    # Logs de sécurité
├── TESTS_REPORT.md           # Rapport de tests détaillé
└── README.md                 # Documentation
```

---

## Exercice 2 : Authentication Enforcer

### Implémentation

Fichier: `security/authentication.js`

**Fonctionnalités:**
- Hachage des mots de passe avec **bcrypt** (cost factor: 10)
- Gestion des sessions avec expiration (30 minutes)
- Protection anti-brute force (verrouillage après 5 tentatives pour 15 minutes)
- Logging de toutes les tentatives de connexion
- Stockage persistant en SQLite

### Réponses aux Questions

#### 1. Quelle méthode de hachage utilisez-vous et pourquoi ?

**Méthode:** Bcrypt avec salt rounds = 10

**Justifications:**
- Résistant au brute force grâce à un coût computationnel ajustable
- Salt automatique unique par mot de passe
- Résistant aux rainbow tables
- Standard industriel éprouvé et recommandé par OWASP
- Protection contre les attaques par GPU

#### 2. Comment gérez-vous le renouvellement des sessions ?

**Mécanisme:**
- Expiration: 30 minutes d'inactivité
- Renouvellement automatique à chaque requête authentifiée
- Mise à jour du timestamp `lastActivity` dans `checkAuthentication()`
- Méthode `renewSession()` pour renouvellement manuel
- Stockage en mémoire avec express-session

#### 3. Que se passe-t-il après 5 tentatives de connexion échouées ?

**Processus:**
1. Comptage des tentatives par utilisateur
2. Après la 5ème tentative: verrouillage du compte pour 15 minutes
3. Logs générés:
   - Tentatives 1-4: `LOGIN_FAILED` (WARNING)
   - 5ème tentative: `ACCOUNT_LOCKED` (CRITICAL)
   - Tentatives suivantes: `LOGIN_BLOCKED` (WARNING)
4. Message utilisateur: "Compte verrouillé. Réessayez dans 15 minutes."
5. Déverrouillage automatique après 15 minutes

---

## Exercice 3 : Authorization RBAC

### Implémentation

Fichier: `security/authorization.js`

**Rôles et permissions:**
- **admin**: `['read', 'write', 'delete', 'admin']`
- **editor**: `['read', 'write']`
- **viewer**: `['read']`

**Méthodes:**
- `can_access(user, resource, action)` - Vérification des permissions
- `requirePermission(permission)` - Middleware Express pour protéger les routes

**Exemple:**
```javascript
app.get('/admin', requirePermission('admin'), (req, res) => {
    // Accessible uniquement aux admins
});
```

---

## Exercice 4 : Input Validation

### Implémentation

Fichier: `security/validation.js`

### 4.1 Validation par Whitelist

**Règles:**

1. **Email:** `/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/`
2. **Mot de passe:**
   - Min 8 caractères
   - 1 majuscule, 1 minuscule, 1 chiffre, 1 spécial (@$!%*?&#)
   - Regex: `/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/`
3. **Username:** `/^[a-zA-Z0-9]{3,20}$/` (3-20 caractères alphanumériques)
4. **Âge:** Entier entre 13 et 120

### 4.2 Protection contre les Injections

**Méthode `sanitizeHtml()`:** Échappe `< > " ' / &`

**Méthode `detectSqlInjection()`:**
Détecte les patterns:
- Commandes SQL: `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, etc.
- Caractères: `--`, `;`, `/*`, `*/`
- Injections: `' OR '...'='`, `UNION SELECT`

**Méthode `detectXss()`:**
Détecte: `<script>`, `javascript:`, `onerror=`, etc.

**Réaction:**
- Blocage de la requête
- Log avec severity CRITICAL
- Message d'erreur générique à l'utilisateur

---

## Exercice 5 : Security Audit Logging

### Implémentation

Fichier: `security/audit.js`

### Format de Log

```json
{
  "timestamp": "2025-11-05T14:30:00.000Z",
  "event_type": "LOGIN_SUCCESS",
  "user": "admin",
  "ip_address": "192.168.1.100",
  "severity": "INFO",
  "details": { "role": "admin" }
}
```

### Types d'Événements

| Événement | Severity | Description |
|-----------|----------|-------------|
| LOGIN_SUCCESS | INFO | Connexion réussie |
| LOGIN_FAILED | WARNING | Échec de connexion |
| LOGIN_BLOCKED | WARNING | Tentative sur compte verrouillé |
| ACCOUNT_LOCKED | CRITICAL | Verrouillage après 5 échecs |
| LOGOUT | INFO | Déconnexion utilisateur |
| SESSION_EXPIRED | INFO | Expiration de session |
| ACCESS_GRANTED | INFO | Accès autorisé |
| ACCESS_DENIED | WARNING | Accès refusé |
| SQL_INJECTION_ATTEMPT | CRITICAL | Injection SQL détectée |
| XSS_ATTEMPT | CRITICAL | XSS détecté |
| USER_CREATED | INFO | Création d'utilisateur |
| ROLE_CHANGED | INFO | Modification du rôle d'un utilisateur |
| PASSWORD_CHANGED | INFO | Changement de mot de passe |
| BRUTE_FORCE_DETECTED | CRITICAL | Attaque brute force détectée |
| ANOMALY_DETECTED | CRITICAL | Anomalie de sécurité |

**Fichier:** `logs/security_audit.log` (format JSON, une ligne par événement)

**Note:** Le système enregistre également d'autres événements comme PERMISSION_CHANGE, ROLE_CREATED, ROLE_UPDATED, LOGS_CLEARED pour une traçabilité complète.

---

## Exercice 6 : Application Complète

### Routes Implémentées

| Route | Méthode | Auth | Permission | Description |
|-------|---------|------|------------|-------------|
| / | GET | Non | - | Redirection vers /login |
| /login | GET/POST | Non | - | Connexion |
| /register | GET/POST | Non | - | Inscription publique (viewer) |
| /dashboard | GET | Oui | - | Dashboard utilisateur |
| /profile | GET | Oui | - | Page de profil utilisateur |
| /profile/change-password | POST | Oui | - | Changer son mot de passe |
| /admin | GET | Oui | admin | Panneau admin |
| /api/users | GET | Oui | admin | Liste des utilisateurs |
| /api/users | POST | Oui | admin | Création utilisateur (avec email et age) |
| /api/users/:username/role | PUT | Oui | admin | Modification du rôle d'un utilisateur |
| /api/logs | GET | Oui | admin | Consultation des logs de sécurité |
| /logout | POST | Oui | - | Déconnexion |

### Sécurités Implémentées

- **Sessions:** HttpOnly cookies, expiration 30 min
- **Rate Limiting:** 5 tentatives/15 min sur /login
- **Validation:** Toutes les entrées utilisateur
- **Détection:** SQL Injection et XSS automatiques
- **Gestion d'erreurs:** Pages d'erreur personnalisées (404, 403, 500)
- **Profil utilisateur:** Changement de mot de passe sécurisé
- **Gestion des rôles:** Interface admin pour modifier les permissions

### Fonctionnalités Avancées

- **Tests automatisés:** Suite de tests de sécurité (`npm test`)
- **Rapport de tests:** Documentation complète dans `TESTS_REPORT.md`
- **Gestion utilisateurs:** Interface admin pour lister et modifier les rôles
- **Profil personnel:** Page dédiée pour consulter ses infos et changer son mot de passe
- **Pages d'erreur:** Templates Bootstrap personnalisés pour 404, 403, 500

---

## Tests de Sécurité

### Tests Automatisés

Exécutez la suite de tests de sécurité:

```bash
npm test
```

Les tests valident:
- Protection contre injection SQL
- Protection contre XSS
- Protection contre brute force
- Contrôle d'accès RBAC
- Expiration de session

Résultats dans: `tests/test-results.json`

### Tests Manuels

### 1. Injection SQL

**Test:**
1. Aller sur /login
2. Username: `admin' OR '1'='1`
3. Password: `anything`

**Résultat attendu:**
- ❌ Connexion refusée
- ✅ Log: `SQL_INJECTION_ATTEMPT` (CRITICAL)
- ✅ Affiché sur /login dans la section "Tentatives d'attaques"

### 2. Cross-Site Scripting (XSS)

**Test:**
1. Se connecter en admin
2. Créer un utilisateur avec username: `<script>alert('XSS')</script>`

**Résultat attendu:**
- ❌ Création refusée
- ✅ Message: "Tentative d'injection détectée"
- ✅ Log: `XSS_ATTEMPT` (CRITICAL)

### 3. Brute Force

**Test:**
Essayer 6 fois de se connecter avec un mauvais mot de passe

**Résultat attendu:**
- Tentatives 1-4: Log `LOGIN_FAILED` (WARNING)
- 5ème: Log `ACCOUNT_LOCKED` (CRITICAL)
- 6ème+: Message "Compte verrouillé. Réessayez dans 15 minutes."

### 4. Escalade de Privilèges

**Test:**
1. Se connecter avec: `viewer` / `Viewer@123`
2. Accéder à /admin

**Résultat attendu:**
- ❌ Accès refusé (403)
- ✅ Log: `ACCESS_DENIED` (WARNING)

### 5. Session Expirée

**Test:**
1. Se connecter
2. Attendre 31 minutes
3. Accéder au dashboard

**Résultat attendu:**
- ❌ Redirection vers /login
- ✅ Log: `SESSION_EXPIRED` (INFO)
- ✅ Message: "Votre session a expiré"

### 6. Validation des Entrées

**Tests de mots de passe:**
- `abc123` → ❌ Trop court
- `Password123` → ❌ Pas de caractère spécial
- `password123!` → ❌ Pas de majuscule
- `Password123!` → ✅ Valide

---

## Documentation des Choix

### Technologiques

**Node.js + Express:**
- Performance asynchrone native
- Écosystème npm riche
- Middleware flexible

**Bcrypt:**
- Standard industriel
- Résistant au brute force
- Salt automatique

**SQLite:**
- Persistance simple
- Pas de serveur externe
- Suffisant pour le TP

**Express-Session:**
- Intégration native
- HttpOnly cookies
- Configuration flexible

### Patterns de Sécurité

**Defense in Depth:**
- Validation + Rate Limiting + Auth + RBAC + Logging

**Least Privilege:**
- Permissions minimales par défaut (viewer)

**Fail Secure:**
- Refus par défaut en cas d'erreur

**Separation of Concerns:**
- Modules séparés pour chaque pattern

---

## Livrables

### 1. Code Source ✅
Tous les fichiers dans `security_app/`

### 2. Documentation ✅
Ce README avec réponses détaillées aux questions

### 3. Tests de Sécurité ✅
6 scénarios de test avec procédures et résultats attendus

### 4. Fichier de Logs ✅
`logs/security_audit.log` généré automatiquement

---

## Conclusion

Application complète implémentant tous les Design Patterns de sécurité demandés:

✅ **Authentication Enforcer** - Bcrypt, sessions, anti-brute force
✅ **Authorization RBAC** - 3 rôles avec permissions granulaires
✅ **Input Validation** - Détection SQL Injection et XSS
✅ **Security Audit Logging** - Logs JSON exhaustifs

**Points forts:**
- Architecture modulaire
- Code sécurisé (OWASP Top 10)
- Interface Bootstrap 5 moderne
- Base de données SQLite persistante
- Tests reproductibles

**Réalisé par:** Amir Moussi
