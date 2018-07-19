import { params } from '../../../servers/dist/globalConfig';
import CoinSig from '../../../servers/dist/CoinSig';
import ElGamal from '../../../servers/dist/ElGamal';
import { getIssuedCoin } from '../../../servers/dist/IssuedCoin';
import { getSigningCoin } from '../../../servers/dist/SigningCoin';


const prepare = () => ([[], []]);

const before = () => {
  const [G, o, g1, g2, e] = params;

  const value = 42;
  const coin_id = G.ctx.BIG.randomnum(G.order, G.rngGen);
  // first we need to create a coin to sign
  const pkBytes_client = [];
  const skBytes_client = [];
  const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
  const pk_client = g1.mul(sk_client);
  sk_client.toBytes(skBytes_client);
  pk_client.toBytes(pkBytes_client);

  const coin_pk_bytes = [];
  const coin_sk = G.ctx.BIG.randomnum(G.order, G.rngGen);
  const coin_pk = G.ctx.PAIR.G2mul(g2, coin_sk);
  coin_pk.toBytes(coin_pk_bytes);


  const sk_issuer_bytes = [];
  const sk_issuer = G.ctx.BIG.randomnum(o, G.rngGen);
  const pk_issuer = g1.mul(sk_issuer);
  sk_issuer.toBytes(sk_issuer_bytes);

  const [ElGamalSK, ElGamalPK] = ElGamal.keygen(params);

  const issuedCoin = getIssuedCoin(coin_pk_bytes, value, pkBytes_client, sk_issuer_bytes);
  const signingCoin = getSigningCoin(issuedCoin, ElGamalPK, coin_id, coin_sk, skBytes_client);

  const [sk, pk] = CoinSig.keygen(params);
  const [h, enc_sig] = CoinSig.mixedSignCoin(params, sk, signingCoin, ElGamalPK);

  const sig = ElGamal.decrypt(params, ElGamalSK, enc_sig);

  const signature = [h, sig];

  const pkX = G.ctx.PAIR.G2mul(pk[4], coin_sk);
  return [pk, signingCoin, signature, coin_id, pkX];
};

const verifyCoin = (pk, coin, sig, id, pkX) => {
  CoinSig.verifyMixedBlindSign(params, pk, coin, sig, id, pkX);
};

const coinVerification = {
  name: 'CoinSignVerify',
  prep: prepare, // should give [a,b] array where a are args for fn and b are args for beforeEach
  beforeEach: before, // returns [c] array which are args for fn
  fn: verifyCoin, // takes ...a, ...c
};

export default coinVerification;
