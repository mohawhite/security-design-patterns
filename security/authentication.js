require('dotenv').config();
const bcrypt = require('bcrypt');
const { SecurityAuditLogger } = require('./audit');
const { DatabaseManager } = require('./database');

class AuthenticationEnforcer {
    constructor() {
        this.sessions = new Map();
        this.failedAttempts = new Map();
        this.sessionTimeout = 30 * 60 * 1000;
        this.maxFailedAttempts = 5;
        this.lockoutDuration = 15 * 60 * 1000;
        this.auditLogger = new SecurityAuditLogger();
        this.db = new DatabaseManager();
        this.ready = this.initialize();
    }

    async initialize() {
        await this.db.initializeDatabase();
        await this.initializeUsers();
    }

    async initializeUsers() {
        const defaultUsers = [
            {
                username: process.env.ADMIN_USERNAME || 'admin',
                password: process.env.ADMIN_PASSWORD || 'Admin@123',
                role: 'admin',
                email: process.env.ADMIN_EMAIL || 'admin@security.local',
                age: null
            },
            {
                username: process.env.EDITOR_USERNAME || 'editor',
                password: process.env.EDITOR_PASSWORD || 'Editor@123',
                role: 'editor',
                email: process.env.EDITOR_EMAIL || 'editor@security.local',
                age: null
            },
            {
                username: process.env.VIEWER_USERNAME || 'viewer',
                password: process.env.VIEWER_PASSWORD || 'Viewer@123',
                role: 'viewer',
                email: process.env.VIEWER_EMAIL || 'viewer@security.local',
                age: null
            }
        ];

        for (const user of defaultUsers) {
            const exists = await this.db.userExists(user.username);
            if (!exists) {
                const hashedPassword = await bcrypt.hash(user.password, 10);
                await this.db.createUser(user.username, hashedPassword, user.role, user.email, user.age);
            }
        }
    }

    async hashPassword(password) {
        return await bcrypt.hash(password, 10);
    }

    async verifyPassword(password, hashedPassword) {
        return await bcrypt.compare(password, hashedPassword);
    }

    isAccountLocked(username) {
        const attempts = this.failedAttempts.get(username);
        if (!attempts) return false;

        if (attempts.count >= this.maxFailedAttempts) {
            const timeSinceLock = Date.now() - attempts.lastAttempt;
            if (timeSinceLock < this.lockoutDuration) {
                return true;
            } else {
                this.failedAttempts.delete(username);
                return false;
            }
        }
        return false;
    }

    recordFailedAttempt(username, ipAddress, credentials) {
        const attempts = this.failedAttempts.get(username) || { count: 0, lastAttempt: 0 };
        attempts.count += 1;
        attempts.lastAttempt = Date.now();
        this.failedAttempts.set(username, attempts);

        this.auditLogger.log({
            event_type: 'LOGIN_FAILED',
            user: username,
            ip_address: ipAddress,
            severity: 'WARNING',
            details: {
                attempt_count: attempts.count,
                username: credentials?.username || username
            }
        });

        if (attempts.count >= this.maxFailedAttempts) {
            this.auditLogger.log({
                event_type: 'ACCOUNT_LOCKED',
                user: username,
                ip_address: ipAddress,
                severity: 'CRITICAL',
                details: {
                    reason: 'Too many failed attempts',
                    username: credentials?.username || username
                }
            });
        }
    }

    resetFailedAttempts(username) {
        this.failedAttempts.delete(username);
    }

    async authenticate(username, password, ipAddress, credentials) {
        if (this.isAccountLocked(username)) {
            this.auditLogger.log({
                event_type: 'LOGIN_BLOCKED',
                user: username,
                ip_address: ipAddress,
                severity: 'WARNING',
                details: {
                    reason: 'Account locked',
                    username: credentials?.username || username
                }
            });
            return { success: false, error: 'Compte verrouillé. Réessayez dans 15 minutes.' };
        }

        const user = await this.db.getUser(username);
        if (!user) {
            this.recordFailedAttempt(username, ipAddress, credentials);
            return { success: false, error: 'Identifiants invalides' };
        }

        const isValid = await this.verifyPassword(password, user.password);
        if (!isValid) {
            this.recordFailedAttempt(username, ipAddress, credentials);
            return { success: false, error: 'Identifiants invalides' };
        }

        this.resetFailedAttempts(username);

        const sessionId = this.generateSessionId();
        const session = {
            userId: username,
            role: user.role,
            createdAt: Date.now(),
            lastActivity: Date.now(),
            ipAddress: ipAddress
        };

        this.sessions.set(sessionId, session);

        this.auditLogger.log({
            event_type: 'LOGIN_SUCCESS',
            user: username,
            ip_address: ipAddress,
            severity: 'INFO',
            details: { role: user.role }
        });

        return { success: true, sessionId, user: { username: user.username, role: user.role } };
    }

    generateSessionId() {
        return require('crypto').randomBytes(32).toString('hex');
    }

    checkAuthentication(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) {
            return { valid: false, error: 'Session invalide' };
        }

        const now = Date.now();
        const sessionAge = now - session.createdAt;
        const inactivityTime = now - session.lastActivity;

        if (sessionAge > this.sessionTimeout || inactivityTime > this.sessionTimeout) {
            this.sessions.delete(sessionId);
            this.auditLogger.log({
                event_type: 'SESSION_EXPIRED',
                user: session.userId,
                ip_address: session.ipAddress,
                severity: 'INFO',
                details: { reason: 'Timeout' }
            });
            return { valid: false, error: 'Session expirée' };
        }

        session.lastActivity = now;
        return { valid: true, userId: session.userId, role: session.role };
    }

    renewSession(sessionId) {
        const session = this.sessions.get(sessionId);
        if (session) {
            session.lastActivity = Date.now();
            return true;
        }
        return false;
    }

    logout(sessionId, ipAddress) {
        const session = this.sessions.get(sessionId);
        if (session) {
            this.auditLogger.log({
                event_type: 'LOGOUT',
                user: session.userId,
                ip_address: ipAddress,
                severity: 'INFO',
                details: {}
            });
            this.sessions.delete(sessionId);
            return true;
        }
        return false;
    }

    async registerUser(username, password, role, email = null, age = null) {
        const exists = await this.db.userExists(username);
        if (exists) {
            return { success: false, error: 'Utilisateur existe déjà' };
        }

        const hashedPassword = await this.hashPassword(password);
        return await this.db.createUser(username, hashedPassword, role, email, age);
    }

    async getAllUsers() {
        return await this.db.getAllUsers();
    }
}

module.exports = { AuthenticationEnforcer };
