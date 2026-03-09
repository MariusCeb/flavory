const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync('flavory.db');

const email = process.argv[2];
if (!email) { console.log('Uso: node activate.js tua@email.com'); process.exit(1); }

db.prepare("UPDATE users SET subscription_status = 'active' WHERE email = ?").run(email);
const user = db.prepare("SELECT name, subscription_status FROM users WHERE email = ?").get(email);
console.log('Fatto!', user);
