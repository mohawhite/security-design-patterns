const { SecurityAuditLogger } = require('./audit');

class AuthorizationEnforcer {
    constructor() {
        this.roles = {
            admin: ['read', 'write', 'delete', 'admin'],
            editor: ['read', 'write'],
            viewer: ['read']
        };
        this.auditLogger = new SecurityAuditLogger();
    }

    can_access(user, resource, action) {
        if (!user || !user.role) {
            this.auditLogger.log({
                event_type: 'ACCESS_DENIED',
                user: user ? user.username : 'unknown',
                ip_address: 'N/A',
                severity: 'WARNING',
                details: { resource, action, reason: 'No user or role' }
            });
            return false;
        }

        const permissions = this.roles[user.role];
        if (!permissions) {
            this.auditLogger.log({
                event_type: 'ACCESS_DENIED',
                user: user.username,
                ip_address: 'N/A',
                severity: 'WARNING',
                details: { resource, action, reason: 'Invalid role' }
            });
            return false;
        }

        const hasPermission = permissions.includes(action);

        if (!hasPermission) {
            this.auditLogger.log({
                event_type: 'ACCESS_DENIED',
                user: user.username,
                ip_address: 'N/A',
                severity: 'WARNING',
                details: { resource, action, reason: 'Insufficient permissions' }
            });
        } else {
            this.auditLogger.log({
                event_type: 'ACCESS_GRANTED',
                user: user.username,
                ip_address: 'N/A',
                severity: 'INFO',
                details: { resource, action }
            });
        }

        return hasPermission;
    }

    getRolePermissions(role) {
        return this.roles[role] || [];
    }

    addRole(roleName, permissions) {
        this.roles[roleName] = permissions;
        this.auditLogger.log({
            event_type: 'ROLE_CREATED',
            user: 'system',
            ip_address: 'N/A',
            severity: 'INFO',
            details: { role: roleName, permissions }
        });
    }

    updateRolePermissions(roleName, permissions) {
        if (!this.roles[roleName]) {
            return false;
        }
        this.roles[roleName] = permissions;
        this.auditLogger.log({
            event_type: 'ROLE_UPDATED',
            user: 'system',
            ip_address: 'N/A',
            severity: 'INFO',
            details: { role: roleName, permissions }
        });
        return true;
    }
}

function requirePermission(permission) {
    return function(req, res, next) {
        if (!req.user) {
            return res.status(401).json({ error: 'Non authentifié' });
        }

        const authEnforcer = new AuthorizationEnforcer();
        const hasPermission = authEnforcer.can_access(req.user, req.path, permission);

        if (!hasPermission) {
            return res.status(403).json({ error: 'Accès refusé' });
        }

        next();
    };
}

module.exports = { AuthorizationEnforcer, requirePermission };
