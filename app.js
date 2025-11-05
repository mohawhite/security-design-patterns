require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const rateLimit = require('express-rate-limit');

const {
    AuthenticationEnforcer,
    AuthorizationEnforcer,
    requirePermission,
    InputValidator,
    SecurityAuditLogger
} = require('./security');

const app = express();
const PORT = 3000;

const authEnforcer = new AuthenticationEnforcer();
const authzEnforcer = new AuthorizationEnforcer();
const validator = new InputValidator();
const auditLogger = new SecurityAuditLogger();

authEnforcer.ready.then(() => {
    console.log('Base de données initialisée avec succès');
}).catch(err => {
    console.error('Erreur initialisation base de données:', err);
});

app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');
app.set('views', path.join(__dirname, 'templates'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'votre-secret-super-securise-a-changer',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 30 * 60 * 1000
    }
}));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Trop de tentatives de connexion, réessayez dans 15 minutes',
    standardHeaders: true,
    legacyHeaders: false,
});

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    const realIp = req.headers['x-real-ip'];
    if (realIp) {
        return realIp;
    }
    let ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    if (ip && ip.startsWith('::ffff:')) {
        ip = ip.substring(7);
    }
    return ip || 'unknown';
}

function authenticationMiddleware(req, res, next) {
    const sessionId = req.session.sessionId;

    if (!sessionId) {
        return res.redirect('/login');
    }

    const authCheck = authEnforcer.checkAuthentication(sessionId);

    if (!authCheck.valid) {
        req.session.destroy();
        return res.redirect('/login?error=session_expired');
    }

    req.user = {
        username: authCheck.userId,
        role: authCheck.role
    };

    next();
}

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    const error = req.query.error;
    let errorMessage = '';

    if (error === 'session_expired') {
        errorMessage = 'Votre session a expiré. Veuillez vous reconnecter.';
    }

    const criticalLogs = auditLogger.getLogs({
        severity: 'CRITICAL',
        limit: 10
    });

    const warningLogs = auditLogger.getLogs({
        severity: 'WARNING',
        limit: 10
    });

    const attacks = [...criticalLogs, ...warningLogs]
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 10);

    res.render('login', { error: errorMessage, attacks });
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const ipAddress = getClientIp(req);

    const usernameValidation = validator.validateInput(username, 'username', ipAddress);
    if (!usernameValidation.valid) {
        const criticalLogs = auditLogger.getLogs({ severity: 'CRITICAL', limit: 10 });
        const warningLogs = auditLogger.getLogs({ severity: 'WARNING', limit: 10 });
        const attacks = [...criticalLogs, ...warningLogs]
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 10);
        return res.render('login', { error: usernameValidation.error, attacks });
    }

    const result = await authEnforcer.authenticate(username, password, ipAddress, { username, password });

    if (!result.success) {
        const criticalLogs = auditLogger.getLogs({ severity: 'CRITICAL', limit: 10 });
        const warningLogs = auditLogger.getLogs({ severity: 'WARNING', limit: 10 });
        const attacks = [...criticalLogs, ...warningLogs]
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 10);
        return res.render('login', { error: result.error, attacks });
    }

    req.session.sessionId = result.sessionId;
    req.session.user = result.user;

    res.redirect('/dashboard');
});

app.get('/dashboard', authenticationMiddleware, (req, res) => {
    res.render('dashboard', { user: req.user });
});

app.get('/admin', authenticationMiddleware, requirePermission('admin'), (req, res) => {
    const logs = auditLogger.getLogs({ limit: 50 });
    res.render('admin', { user: req.user, logs });
});

app.post('/api/users', authenticationMiddleware, requirePermission('admin'), async (req, res) => {
    const { username, password, email, age, role } = req.body;
    const ipAddress = getClientIp(req);

    const validation = validator.validateUserRegistration(
        { username, password, email, age },
        ipAddress
    );

    if (!validation.valid) {
        return res.status(400).json({
            success: false,
            errors: validation.errors
        });
    }

    const validRoles = ['admin', 'editor', 'viewer'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({
            success: false,
            error: 'Rôle invalide'
        });
    }

    const result = await authEnforcer.registerUser(username, password, role, email, age);

    if (!result.success) {
        return res.status(400).json(result);
    }

    auditLogger.log({
        event_type: 'USER_CREATED',
        user: req.user.username,
        ip_address: ipAddress,
        severity: 'INFO',
        details: { new_user: username, role, email, age }
    });

    res.json({ success: true, message: 'Utilisateur créé avec succès' });
});

app.get('/api/logs', authenticationMiddleware, requirePermission('admin'), (req, res) => {
    const { event_type, user, severity, limit } = req.query;

    const logs = auditLogger.getLogs({
        event_type,
        user,
        severity,
        limit: limit ? parseInt(limit) : 100
    });

    res.json({ logs });
});

app.post('/logout', authenticationMiddleware, (req, res) => {
    const ipAddress = getClientIp(req);
    authEnforcer.logout(req.session.sessionId, ipAddress);
    req.session.destroy();
    res.redirect('/login');
});

app.get('/register', (req, res) => {
    res.render('register', { error: null, success: null });
});

app.post('/register', async (req, res) => {
    const { username, email, password, confirm_password } = req.body;
    const ipAddress = getClientIp(req);

    if (password !== confirm_password) {
        return res.render('register', {
            error: 'Les mots de passe ne correspondent pas',
            success: null
        });
    }

    const validation = validator.validateUserRegistration(
        { username, password, email },
        ipAddress
    );

    if (!validation.valid) {
        const errorMessages = Object.values(validation.errors).join(', ');
        return res.render('register', {
            error: errorMessages,
            success: null
        });
    }

    const result = await authEnforcer.registerUser(username, password, 'viewer', email);

    if (!result.success) {
        return res.render('register', {
            error: result.error,
            success: null
        });
    }

    auditLogger.log({
        event_type: 'USER_CREATED',
        user: username,
        ip_address: ipAddress,
        severity: 'INFO',
        details: { role: 'viewer', source: 'self-registration', email }
    });

    res.render('register', {
        error: null,
        success: 'Compte créé avec succès ! Vous pouvez maintenant vous connecter.'
    });
});


app.use((err, req, res, next) => {
    const ipAddress = getClientIp(req);

    auditLogger.log({
        event_type: 'ERROR',
        user: req.user ? req.user.username : 'anonymous',
        ip_address: ipAddress,
        severity: 'ERROR',
        details: {
            message: err.message,
            stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
        }
    });

    res.status(500).json({
        error: 'Une erreur interne s\'est produite'
    });
});

app.listen(PORT, () => {
    console.log(`Serveur démarré sur http://localhost:${PORT}`);
    console.log('\nComptes par défaut:');
    console.log(`- Admin: ${process.env.ADMIN_USERNAME || 'admin'} / ${process.env.ADMIN_PASSWORD || 'Admin@123'}`);
    console.log(`- Editor: ${process.env.EDITOR_USERNAME || 'editor'} / ${process.env.EDITOR_PASSWORD || 'Editor@123'}`);
    console.log(`- Viewer: ${process.env.VIEWER_USERNAME || 'viewer'} / ${process.env.VIEWER_PASSWORD || 'Viewer@123'}`);
});
