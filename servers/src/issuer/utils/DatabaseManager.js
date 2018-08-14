import * as pg from 'pg';
import { DEBUG, pgConfig } from '../config/appConfig';

const pool = new pg.Pool(pgConfig);

export const getBalance = async (pk_bytes) => {
  let balance = -1;
  try {
    const str_pk_bytes = pk_bytes.join('');
    const res = await pool.query('\
      SELECT "Balance" \
      FROM public."tblClients"\
      WHERE "Public Key" = $1', [str_pk_bytes]);

    if (DEBUG) {
      console.log(`Queried balance for ${str_pk_bytes} which is is ${res.rows[0].Balance}`);
    }

    balance = res.rows[0].Balance;
  } catch (err) {
    if (DEBUG) {
      console.log('Query for balance was unsuccessful');
    }
  }
  return balance;
};

// if given user does not exist, it creates him and sets his balance to the value
export const changeBalance = async (pk_bytes, value) => {
  const str_pk_bytes = pk_bytes.join('');

  await pool.query('\
  INSERT INTO public."tblClients" ("Public Key", "Balance")\
    VALUES ($1, $2)\
    ON CONFLICT \
    ON CONSTRAINT "tblClients_pkey"\
    DO UPDATE SET "Balance" = public."tblClients"."Balance" + $2', [str_pk_bytes, value]);

  if (DEBUG) {
    console.log(`Updated balance of ${str_pk_bytes} by ${value}`);
  }
};

export const insertUsedId = async (id) => {
  const id_str = id.toString();
  await pool.query('\
  INSERT INTO public."tblUsedIds"\
  ("Id")\
  VALUES ($1)', [id_str]);

  if (DEBUG) {
    console.log(`Inserted ${id_str} to UsedIds`);
  }
};

export const checkUsedId = async (id) => {
  const res = await pool.query('\
  SELECT (1)\
  FROM public."tblUsedIds"\
  WHERE "Id" = $1', [id]);

  const wasUsed = res.rows.length;
  if (DEBUG) {
    console.log(`Checked if cred id ${id} was already used and result was: ${wasUsed}`);
  }

  return (wasUsed !== 0);
};
