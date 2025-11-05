const { SecurityAuditLogger } = require('./audit');

class InputValidator {
    constructor() {
        this.auditLogger = new SecurityAuditLogger();
        this.emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
        this.passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;
        this.usernameRegex = /^[a-zA-Z0-9]{3,20}$/;
        this.sqlInjectionPatterns = [
            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)/i,
            /(--|\;|\/\*|\*\/|xp_|sp_)/i,
            /(\bOR\b|\bAND\b).*=.*=/i,
            /'.*OR.*'.*=.*'/i,
            /\bUNION\b.*\bSELECT\b/i
        ];
        this.xssPatterns = [
            /<script[^>]*>.*?<\/script>/gi,
            /<iframe[^>]*>.*?<\/iframe>/gi,
            /javascript:/gi,
            /on\w+\s*=/gi,
            /<img[^>]*onerror/gi
        ];
    }

    validateEmail(email) {
        if (!email || typeof email !== 'string') {
            return { valid: false, error: 'Email requis' };
        }

        if (!this.emailRegex.test(email)) {
            return { valid: false, error: 'Format d\'email invalide' };
        }

        return { valid: true };
    }

    validatePassword(password) {
        if (!password || typeof password !== 'string') {
            return { valid: false, error: 'Mot de passe requis' };
        }

        if (password.length < 8) {
            return { valid: false, error: 'Le mot de passe doit contenir au moins 8 caractères' };
        }

        if (!this.passwordRegex.test(password)) {
            return {
                valid: false,
                error: 'Le mot de passe doit contenir au moins 1 majuscule, 1 minuscule, 1 chiffre et 1 caractère spécial (@$!%*?&#)'
            };
        }

        return { valid: true };
    }

    validateUsername(username) {
        if (!username || typeof username !== 'string') {
            return { valid: false, error: 'Nom d\'utilisateur requis' };
        }

        if (!this.usernameRegex.test(username)) {
            return { valid: false, error: 'Le nom d\'utilisateur doit contenir 3-20 caractères alphanumériques' };
        }

        return { valid: true };
    }

    validateAge(age) {
        const ageNum = parseInt(age, 10);

        if (isNaN(ageNum)) {
            return { valid: false, error: 'L\'âge doit être un nombre' };
        }

        if (ageNum < 13 || ageNum > 120) {
            return { valid: false, error: 'L\'âge doit être entre 13 et 120' };
        }

        return { valid: true };
    }

    sanitizeHtml(input) {
        if (!input || typeof input !== 'string') {
            return '';
        }

        const escapeMap = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '/': '&#x2F;',
            '&': '&amp;'
        };

        return input.replace(/[<>"'/&]/g, (char) => escapeMap[char]);
    }

    detectSqlInjection(input, ipAddress = 'N/A') {
        if (!input || typeof input !== 'string') {
            return { detected: false };
        }

        for (const pattern of this.sqlInjectionPatterns) {
            if (pattern.test(input)) {
                this.auditLogger.log({
                    event_type: 'SQL_INJECTION_ATTEMPT',
                    user: 'unknown',
                    ip_address: ipAddress,
                    severity: 'CRITICAL',
                    details: { input: input.substring(0, 100), pattern: pattern.toString() }
                });
                return { detected: true, type: 'SQL Injection' };
            }
        }

        return { detected: false };
    }

    detectXss(input, ipAddress = 'N/A') {
        if (!input || typeof input !== 'string') {
            return { detected: false };
        }

        for (const pattern of this.xssPatterns) {
            if (pattern.test(input)) {
                this.auditLogger.log({
                    event_type: 'XSS_ATTEMPT',
                    user: 'unknown',
                    ip_address: ipAddress,
                    severity: 'CRITICAL',
                    details: { input: input.substring(0, 100), pattern: pattern.toString() }
                });
                return { detected: true, type: 'XSS' };
            }
        }

        return { detected: false };
    }

    validateInput(input, type, ipAddress = 'N/A') {
        const sqlCheck = this.detectSqlInjection(input, ipAddress);
        if (sqlCheck.detected) {
            return { valid: false, error: 'Tentative d\'injection détectée' };
        }

        const xssCheck = this.detectXss(input, ipAddress);
        if (xssCheck.detected) {
            return { valid: false, error: 'Tentative d\'injection détectée' };
        }

        switch (type) {
            case 'email':
                return this.validateEmail(input);
            case 'password':
                return this.validatePassword(input);
            case 'username':
                return this.validateUsername(input);
            case 'age':
                return this.validateAge(input);
            default:
                return { valid: true };
        }
    }

    validateUserRegistration(data, ipAddress = 'N/A') {
        const errors = {};

        const usernameValidation = this.validateInput(data.username, 'username', ipAddress);
        if (!usernameValidation.valid) {
            errors.username = usernameValidation.error;
        }

        const passwordValidation = this.validateInput(data.password, 'password', ipAddress);
        if (!passwordValidation.valid) {
            errors.password = passwordValidation.error;
        }

        if (data.email) {
            const emailValidation = this.validateInput(data.email, 'email', ipAddress);
            if (!emailValidation.valid) {
                errors.email = emailValidation.error;
            }
        }

        if (data.age) {
            const ageValidation = this.validateInput(data.age, 'age', ipAddress);
            if (!ageValidation.valid) {
                errors.age = ageValidation.error;
            }
        }

        return {
            valid: Object.keys(errors).length === 0,
            errors
        };
    }
}

module.exports = { InputValidator };
