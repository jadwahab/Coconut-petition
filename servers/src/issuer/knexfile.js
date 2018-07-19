import { POSTGRES_USER, POSTGRES_DB, POSTGRES_PASSWORD, hostname } from './config/appConfig';


module.exports = {
  development: {
    client: 'pg',
    connection: {
      host: hostname,
      user: POSTGRES_USER,
      password: POSTGRES_PASSWORD,
      database: POSTGRES_DB,
    },
    migrations: {
      directory: '../../issuerdb/migrations',
      tableName: 'knex_migrations',
    },
    seeds: {
      directory: '../../issuerdb/seeds',
    },
  },

  production: {
    client: 'pg',
    connection: {
      host: hostname,
      user: POSTGRES_USER,
      password: POSTGRES_PASSWORD,
      database: POSTGRES_DB,
    },
    migrations: {
      directory: '../../issuerdb/migrations',
      tableName: 'knex_migrations',
    },
    seeds: {
      directory: '../../issuerdb/seeds',
    },
  },

};
