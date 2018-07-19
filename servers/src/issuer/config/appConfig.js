export const hostname = '127.0.0.1';
export const DEBUG = false;
export const FAKE_BALANCE = true;
export const POSTGRES_USER = 'issuer';
export const POSTGRES_PASSWORD = 'secretpassword';
export const POSTGRES_DB = 'issuerdb';
export const POSTGRES_PORT = '5432';

export const pgConfig = {
  database: POSTGRES_DB,
  user: POSTGRES_USER,
  password: POSTGRES_PASSWORD,
  host: hostname,
  port: POSTGRES_PORT,
  max: 10, // max number of clients in the pool
  idleTimeoutMillis: 30000, // how long a client is allowed to remain idle before being closed
};
