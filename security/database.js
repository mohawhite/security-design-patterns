const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class DatabaseManager {
    constructor() {
        const dbPath = path.join(__dirname, '..', 'database.sqlite');
        this.db = new sqlite3.Database(dbPath);
        this.initialized = false;
    }

    initializeDatabase() {
        return new Promise((resolve, reject) => {
            this.db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    email TEXT,
                    age INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            `, (err) => {
                if (err) {
                    reject(err);
                } else {
                    this.initialized = true;
                    resolve();
                }
            });
        });
    }

    createUser(username, password, role, email = null, age = null) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO users (username, password, role, email, age) VALUES (?, ?, ?, ?, ?)',
                [username, password, role, email, age],
                function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE constraint')) {
                            resolve({ success: false, error: 'Utilisateur existe déjà' });
                        } else {
                            resolve({ success: false, error: err.message });
                        }
                    } else {
                        resolve({ success: true });
                    }
                }
            );
        });
    }

    getUser(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    getAllUsers() {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT username, role, created_at FROM users',
                [],
                (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows);
                    }
                }
            );
        });
    }

    updateUser(username, updates) {
        return new Promise((resolve, reject) => {
            const fields = [];
            const values = [];

            if (updates.password) {
                fields.push('password = ?');
                values.push(updates.password);
            }
            if (updates.role) {
                fields.push('role = ?');
                values.push(updates.role);
            }

            if (fields.length === 0) {
                resolve({ success: false, error: 'Aucune mise à jour' });
                return;
            }

            values.push(username);
            this.db.run(
                `UPDATE users SET ${fields.join(', ')} WHERE username = ?`,
                values,
                function(err) {
                    if (err) {
                        resolve({ success: false, error: err.message });
                    } else {
                        resolve({ success: this.changes > 0 });
                    }
                }
            );
        });
    }

    deleteUser(username) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'DELETE FROM users WHERE username = ?',
                [username],
                function(err) {
                    if (err) {
                        resolve({ success: false, error: err.message });
                    } else {
                        resolve({ success: this.changes > 0 });
                    }
                }
            );
        });
    }

    userExists(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT COUNT(*) as count FROM users WHERE username = ?',
                [username],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row.count > 0);
                    }
                }
            );
        });
    }

    close() {
        this.db.close();
    }
}

module.exports = { DatabaseManager };
