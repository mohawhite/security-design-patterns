const { AuthenticationEnforcer } = require('./authentication');
const { AuthorizationEnforcer, requirePermission } = require('./authorization');
const { InputValidator } = require('./validation');
const { SecurityAuditLogger } = require('./audit');

module.exports = {
    AuthenticationEnforcer,
    AuthorizationEnforcer,
    requirePermission,
    InputValidator,
    SecurityAuditLogger
};
