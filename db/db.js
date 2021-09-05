const { Pool } = require('pg');

const devConfig = `postgresql://${process.env.PGUSER}:${process.env.PGPASSWORD}@${process.env.PGHOST}:${process.env.PGPORT}/${process.env.PGDATABASE}`;

const prodConfig = process.env.DATABASE_URL; //heroku addons

const pool = new Pool({
  connectionString:
    process.env.NODE_ENV === "production" ? prodConfig : devConfig,
    
});

pool.query('SELECT NOW()').then(res => {
    console.log('Connected to database');
}).catch(err => console.log(err));

module.exports = pool;