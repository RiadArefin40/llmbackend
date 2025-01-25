const mysql = require('mysql2');
require('dotenv').config();

const db = mysql.createConnection({
    host: mysql.railway.internal,
    user: root,
    password: vpqLyOPsYJqGvEcHqUVpAJfhfWGEYkxf,
    database:railway
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to the MySQL database!');
});

module.exports = db;
