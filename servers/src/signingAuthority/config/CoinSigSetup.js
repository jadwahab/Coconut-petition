import { ctx } from '../../globalConfig'; // required to resolve circular dependency issue
import CoinSig from '../../CoinSig';

export const params = [];
export const pk = [];
export const pkBytes = [];
export const sk = [];

export const setupCoinSigKeys = () => {
  const params_gen = CoinSig.setup();
  const [sk_gen, pk_gen] = CoinSig.keygen(params_gen);
  for (let i = 0; i < params_gen.length; i++) { params[i] = params_gen[i]; }
  for (let i = 0; i < sk_gen.length; i++) { sk[i] = sk_gen[i]; }
  for (let i = 0; i < pk_gen.length; i++) { pk[i] = pk_gen[i]; }

  const [g, X, Y] = pk_gen;
  // for sending to petitionOwner later, we'll also need byte representation
  const g2_bytes = [];
  const X_bytes = [];
  const Y_bytes = [];

  g.toBytes(g2_bytes);
  X.toBytes(X_bytes);
  Y.toBytes(Y_bytes);

  pkBytes.push(g2_bytes);
  pkBytes.push(X_bytes);
  pkBytes.push(Y_bytes);

  console.log('Generated CoinSig secret and public sigKeys');
};
