const fs = require('fs');
const path = require('path');

class SecurityAuditLogger {
    constructor() {
        this.logDir = path.join(__dirname, '..', 'logs');
        this.logFile = path.join(this.logDir, 'security_audit.log');
        this.ensureLogDirectory();
    }

    ensureLogDirectory() {
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir, { recursive: true });
        }
    }

    log(eventData) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            event_type: eventData.event_type,
            user: eventData.user || 'unknown',
            ip_address: eventData.ip_address || 'N/A',
            severity: eventData.severity || 'INFO',
            details: eventData.details || {}
        };

        const logLine = JSON.stringify(logEntry) + '\n';

        try {
            fs.appendFileSync(this.logFile, logLine);
        } catch (error) {
            console.error('Erreur lors de l\'écriture du log:', error);
        }

        if (logEntry.severity === 'CRITICAL' || logEntry.severity === 'ERROR') {
            console.error(`[${logEntry.severity}] ${logEntry.event_type}:`, logEntry);
        }
    }

    logLoginAttempt(username, success, ipAddress, details = {}) {
        this.log({
            event_type: success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
            user: username,
            ip_address: ipAddress,
            severity: success ? 'INFO' : 'WARNING',
            details: { success, ...details }
        });
    }

    logAccessAttempt(user, resource, action, granted, ipAddress) {
        this.log({
            event_type: granted ? 'ACCESS_GRANTED' : 'ACCESS_DENIED',
            user: user,
            ip_address: ipAddress,
            severity: granted ? 'INFO' : 'WARNING',
            details: { resource, action }
        });
    }

    logPermissionChange(adminUser, targetUser, oldRole, newRole, ipAddress) {
        this.log({
            event_type: 'PERMISSION_CHANGE',
            user: adminUser,
            ip_address: ipAddress,
            severity: 'INFO',
            details: { target_user: targetUser, old_role: oldRole, new_role: newRole }
        });
    }

    logAnomaly(anomalyType, details, ipAddress, user = 'unknown') {
        this.log({
            event_type: 'ANOMALY_DETECTED',
            user: user,
            ip_address: ipAddress,
            severity: 'CRITICAL',
            details: { anomaly_type: anomalyType, ...details }
        });
    }

    logBruteForce(username, attemptCount, ipAddress) {
        this.log({
            event_type: 'BRUTE_FORCE_DETECTED',
            user: username,
            ip_address: ipAddress,
            severity: 'CRITICAL',
            details: { attempt_count: attemptCount }
        });
    }

    getLogs(filterOptions = {}) {
        try {
            if (!fs.existsSync(this.logFile)) {
                return [];
            }

            const logContent = fs.readFileSync(this.logFile, 'utf-8');
            const logs = logContent
                .split('\n')
                .filter(line => line.trim())
                .map(line => {
                    try {
                        return JSON.parse(line);
                    } catch {
                        return null;
                    }
                })
                .filter(log => log !== null);

            let filteredLogs = logs;

            if (filterOptions.event_type) {
                filteredLogs = filteredLogs.filter(log => log.event_type === filterOptions.event_type);
            }

            if (filterOptions.user) {
                filteredLogs = filteredLogs.filter(log => log.user === filterOptions.user);
            }

            if (filterOptions.severity) {
                filteredLogs = filteredLogs.filter(log => log.severity === filterOptions.severity);
            }

            if (filterOptions.limit) {
                filteredLogs = filteredLogs.slice(-filterOptions.limit);
            }

            return filteredLogs;
        } catch (error) {
            console.error('Erreur lors de la lecture des logs:', error);
            return [];
        }
    }

    clearLogs() {
        try {
            fs.writeFileSync(this.logFile, '');
            this.log({
                event_type: 'LOGS_CLEARED',
                user: 'system',
                ip_address: 'N/A',
                severity: 'INFO',
                details: {}
            });
        } catch (error) {
            console.error('Erreur lors de la suppression des logs:', error);
        }
    }
}

module.exports = { SecurityAuditLogger };
