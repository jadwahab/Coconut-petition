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

  const [g, X0, X1, X2, X3, X4] = pk_gen;
  // for sending to merchant later, we'll also need byte representation
  const g2_bytes = [];
  const X0_bytes = [];
  const X1_bytes = [];
  const X2_bytes = [];
  const X3_bytes = [];
  const X4_bytes = [];

  g.toBytes(g2_bytes);
  X0.toBytes(X0_bytes);
  X1.toBytes(X1_bytes);
  X2.toBytes(X2_bytes);
  X3.toBytes(X3_bytes);
  X4.toBytes(X4_bytes);

  pkBytes.push(g2_bytes);
  pkBytes.push(X0_bytes);
  pkBytes.push(X1_bytes);
  pkBytes.push(X2_bytes);
  pkBytes.push(X3_bytes);
  pkBytes.push(X4_bytes);

  console.log('Generated CoinSig secret and public sigKeys');
};
