import { ctx } from '../../globalConfig'; // required to resolve circular dependency issue
import CredSig from '../../CredSig';
import ElGamal from '../../ElGamal';

export const params = [];
export const pk = [];
export const pkBytes = [];
export const sk = [];
export const ElGamalkeys = [];
export const pkElGamalBytes = [];

export const setupCredSigKeys = () => {
  const params_gen = CredSig.setup();
  const [sk_gen, pk_gen] = CredSig.keygen(params_gen);
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

  // El Gamal key:
  const [skElGamal_gen, pkElGamal_gen] = ElGamal.keygen(params);
  
  ElGamalkeys.push(skElGamal_gen);
  ElGamalkeys.push(pkElGamal_gen);

  pkElGamal_gen.toBytes(pkElGamalBytes);

  console.log('Generated CredSig secret and public sigKeys + ElGamal keypair');
};
