// A slightly modified Pointcheval-Sanders Short Randomizable Signatures scheme
// to allow for larger number of signed messages from multiple authorities

import BpGroup from './BpGroup';
import { ctx } from './globalConfig';
import { hashToBIG, hashG2ElemToBIG, hashToPointOnCurve, hashMessage } from './auxiliary';
import ElGamal from './ElGamal';

export default class CoinSig {
  static setup() {
    const G = new BpGroup();

    const g1 = G.gen1;
    const g2 = G.gen2;
    const e = G.pair;
    const o = G.order;

    return [G, o, g1, g2, e];
  }

// note: x1 is there because of the value parameter but commented out
//       to be deleted if not needed anymore later

  static keygen(params) {
    const [G, o, g1, g2, e] = params;

    const x0 = G.ctx.BIG.randomnum(G.order, G.rngGen);
    const x1 = G.ctx.BIG.randomnum(G.order, G.rngGen);
    const x2 = G.ctx.BIG.randomnum(G.order, G.rngGen);
    const x3 = G.ctx.BIG.randomnum(G.order, G.rngGen);
    const x4 = G.ctx.BIG.randomnum(G.order, G.rngGen);

    const X0 = G.ctx.PAIR.G2mul(g2, x0);
    const X1 = G.ctx.PAIR.G2mul(g2, x1);
    const X2 = G.ctx.PAIR.G2mul(g2, x2);
    const X3 = G.ctx.PAIR.G2mul(g2, x3);
    const X4 = G.ctx.PAIR.G2mul(g2, x4);

    const sk = [x0, x1, x2, x3, x4];
    const pk = [g2, X0, X1, X2, X3, X4];

    return [sk, pk];
  }

  // sig = (x0 + x1*a1 + x2*a2 + x3*a3 + x4*a4) * h
  static sign(params, sk, coin) {
    const [G, o, g1, g2, e] = params;
    const [x0, x1, x2, x3, x4] = sk;

    const h = hashToPointOnCurve(coin.ttl.toString() + coin.v.toString() + coin.ID.toString());

    // const a1 = new G.ctx.BIG(coin.value);
    // a1.norm();
    const a2 = hashToBIG(coin.ttl.toString());

    // this is replaced in blind signature
    const a3 = hashG2ElemToBIG(coin.v);
    const a4 = hashG2ElemToBIG(coin.ID);

    // calculate a1 mod p, a2 mod p, etc.
    // const a1_cpy = new G.ctx.BIG(a1);
    // a1_cpy.mod(o);

    const a2_cpy = new G.ctx.BIG(a2);
    a2_cpy.mod(o);

    const a3_cpy = new G.ctx.BIG(a3);
    a3_cpy.mod(o);

    const a4_cpy = new G.ctx.BIG(a4);
    a4_cpy.mod(o);

    // calculate t1 = x1 * (a1 mod p), t2 = x2 * (a2 mod p), etc.
    // const t1 = G.ctx.BIG.mul(x1, a1_cpy);
    const t2 = G.ctx.BIG.mul(x2, a2_cpy);
    const t3 = G.ctx.BIG.mul(x3, a3_cpy);
    const t4 = G.ctx.BIG.mul(x4, a4_cpy);

    // DBIG constructor does not allow to pass it a BIG value hence we copy all word values manually
    const x0DBIG = new G.ctx.DBIG(0);
    for (let i = 0; i < G.ctx.BIG.NLEN; i++) {
      x0DBIG.w[i] = x0.w[i];
    }

    // x0 + t1 + t2 + ...
    // x0DBIG.add(t1);
    x0DBIG.add(t2);
    x0DBIG.add(t3);
    x0DBIG.add(t4);

    // K = (x0 + x1*a1 + x2*a2 + ...) mod p
    const K = x0DBIG.mod(o);

    // sig = K * h
    const sig = G.ctx.PAIR.G1mul(h, K);

    return [h, sig];
  }

  //  e(sig1, X0 + a1 * X1 + ...) == e(sig2, g)
  static verify(params, pk, coin, sig) {
    // if aggregation failed because h differed
    if (!sig) {
      return false;
    }
    const [G, o, g1, g2, e] = params;
    const [g, X0, X1, X2, X3, X4] = pk;
    const [sig1, sig2] = sig;

    // const a1 = new G.ctx.BIG(coin.value);
    // a1.norm();
    const a2 = hashToBIG(coin.ttl.toString());
    const a3 = hashG2ElemToBIG(coin.v);
    const a4 = hashG2ElemToBIG(coin.ID);

    // const G2_tmp1 = G.ctx.PAIR.G2mul(X1, a1);
    const G2_tmp2 = G.ctx.PAIR.G2mul(X2, a2);
    const G2_tmp3 = G.ctx.PAIR.G2mul(X3, a3);
    const G2_tmp4 = G.ctx.PAIR.G2mul(X4, a4);

    // so that the original key wouldn't be mutated
    const X0_cpy = new G.ctx.ECP2();

    X0_cpy.copy(X0);
    // X0_cpy.add(G2_tmp1);
    X0_cpy.add(G2_tmp2);
    X0_cpy.add(G2_tmp3);
    X0_cpy.add(G2_tmp4);

    X0_cpy.affine();

    // for some reason sig1.x, sig1.y, sig2.x and sig2.y return false to being instances of FP when signed by SAs,
    // hence temporary, ugly hack:
    // I blame javascript pseudo-broken typesystem
    const tempX1 = new G.ctx.FP(0);
    const tempY1 = new G.ctx.FP(0);
    tempX1.copy(sig1.getx());
    tempY1.copy(sig1.gety());
    sig1.x = tempX1;
    sig1.y = tempY1;

    const tempX2 = new G.ctx.FP(0);
    const tempY2 = new G.ctx.FP(0);
    tempX2.copy(sig2.getx());
    tempY2.copy(sig2.gety());
    sig2.x = tempX2;
    sig2.y = tempY2;

    const Gt_1 = e(sig1, X0_cpy);
    const Gt_2 = e(sig2, g);

    return !sig2.INF && Gt_1.equals(Gt_2);
  }

  static randomize(params, sig) {
    const [G, o, g1, g2, e] = params;
    const [sig1, sig2] = sig;
    const t = G.ctx.BIG.randomnum(G.order, G.rngGen);

    return [G.ctx.PAIR.G1mul(sig1, t), G.ctx.PAIR.G1mul(sig2, t)];
  }

  static aggregateSignatures(params, signatures) {
    const [G, o, g1, g2, e] = params;

    const aggregateSignature = new G.ctx.ECP();
    aggregateSignature.copy(signatures[0][1]);

    for (let i = 1; i < signatures.length; i++) {
      if (!signatures[0][0].equals(signatures[i][0])) {
        console.warn('Invalid signatures provided');
        return null;
      }
      aggregateSignature.add(signatures[i][1]);
    }

    aggregateSignature.affine();
    return [signatures[0][0], aggregateSignature];
  }

  static aggregatePublicKeys(params, pks) {
    const [G, o, g1, g2, e] = params;

    const ag = new G.ctx.ECP2();
    const aX0 = new G.ctx.ECP2();
    const aX1 = new G.ctx.ECP2();
    const aX2 = new G.ctx.ECP2();
    const aX3 = new G.ctx.ECP2();
    const aX4 = new G.ctx.ECP2();

    for (let i = 0; i < pks.length; i++) {
      const [g, X0, X1, X2, X3, X4] = pks[i];
      if (i === 0) {
        ag.copy(g);
        aX0.copy(X0);
        aX1.copy(X1);
        aX2.copy(X2);
        aX3.copy(X3);
        aX4.copy(X4);
      } else {
        aX0.add(X0);
        aX1.add(X1);
        aX2.add(X2);
        aX3.add(X3);
        aX4.add(X4);
      }
    }
    aX0.affine();
    aX1.affine();
    aX2.affine();
    aX3.affine();
    aX4.affine();

    return [ag, aX0, aX1, aX2, aX3, aX4];
  }

  static verifyAggregation(params, pks, coin, aggregateSignature) {
    const aPk = CoinSig.aggregatePublicKeys(params, pks);
    return CoinSig.verify(params, aPk, coin, aggregateSignature);
  }

  // no need to pass h - encryption is already using it
  static blindSignComponent(sk_component, encrypted_param) {
    const [encrypted_param_a, encrypted_param_b] = encrypted_param;
    const sig_a = ctx.PAIR.G1mul(encrypted_param_a, sk_component);
    const sig_b = ctx.PAIR.G1mul(encrypted_param_b, sk_component);

    return [sig_a, sig_b];
  }

  static mixedSignCoin(params, sk, signingCoin, ElGamalPK) {
    const [G, o, g1, g2, e] = params;
    const [x0, x1, x2, x3, x4] = sk;

    const reducer = (acc, cur) => acc + cur;

    const coinStr =
      signingCoin.pk_client_bytes.reduce(reducer) + // client's key
      // signingCoin.value.toString() + // coin's value
      signingCoin.pk_coin_bytes.reduce(reducer) + // coin's pk
      signingCoin.ttl.toString() +
      signingCoin.issuedCoinSig[0].reduce(reducer) +
      signingCoin.issuedCoinSig[1].reduce(reducer);

    const h = hashToPointOnCurve(coinStr);

    const enc_sk = [ctx.ECP.fromBytes(signingCoin.enc_sk_bytes[0]), ctx.ECP.fromBytes(signingCoin.enc_sk_bytes[1])];
    const enc_id = [ctx.ECP.fromBytes(signingCoin.enc_id_bytes[0]), ctx.ECP.fromBytes(signingCoin.enc_id_bytes[1])];

    // const a1 = new G.ctx.BIG(signingCoin.value);
    // a1.norm();
    const a2 = hashToBIG(signingCoin.ttl.toString());

    const [enc_sk_component_a, enc_sk_component_b] = CoinSig.blindSignComponent(x3, enc_sk);
    const [enc_id_component_a, enc_id_component_b] = CoinSig.blindSignComponent(x4, enc_id);

    // calculate a1 mod p, a2 mod p, etc.

    // a1 to do with value removed
    // const a1_cpy = new G.ctx.BIG(a1);
    // a1_cpy.mod(o);

    const a2_cpy = new G.ctx.BIG(a2);
    a2_cpy.mod(o);

    // calculate t1 = x1 * (a1 mod p), t2 = x2 * (a2 mod p)

    // t1 -> a1 -> value removed
    // const t1 = G.ctx.BIG.mul(x1, a1_cpy);
    const t2 = G.ctx.BIG.mul(x2, a2_cpy);

    // DBIG constructor does not allow to pass it a BIG value hence we copy all word values manually
    const x0DBIG = new G.ctx.DBIG(0);
    for (let i = 0; i < G.ctx.BIG.NLEN; i++) {
      x0DBIG.w[i] = x0.w[i];
    }

    // t1 removed
    // x0DBIG.add(t1);

    x0DBIG.add(t2);

    // K = (x0 + x1*a1 + x2*a2) mod p
    const K = x0DBIG.mod(o);

    // sig = K * h
    // const val_ttl_sig_component = G.ctx.PAIR.G1mul(h, K); // this is done during encryption below

    const [val_ttl_sig_a, val_ttl_sig_b, k] = ElGamal.encrypt(params, ElGamalPK, K, h);
    const encrypted_full_signature_a = new G.ctx.ECP();
    encrypted_full_signature_a.copy(val_ttl_sig_a);
    encrypted_full_signature_a.add(enc_sk_component_a);
    encrypted_full_signature_a.add(enc_id_component_a);
    encrypted_full_signature_a.affine();

    const encrypted_full_signature_b = new G.ctx.ECP();
    encrypted_full_signature_b.copy(val_ttl_sig_b);
    encrypted_full_signature_b.add(enc_sk_component_b);
    encrypted_full_signature_b.add(enc_id_component_b);
    encrypted_full_signature_b.affine();

    return [h, [encrypted_full_signature_a, encrypted_full_signature_b]];
  }

  // assumes id has already been revealed and proof of knowledge of x provided
  static verifyMixedBlindSign(params, pk, coin, sig, id, pkX) {
    if (!sig) {
      return false;
    }
    const [G, o, g1, g2, e] = params;
    const [g, X0, X1, X2, X3, X4] = pk;
    const [sig1, sig2] = sig;

    // const a1 = new G.ctx.BIG(coin.value);
    // a1.norm();
    const a2 = hashToBIG(coin.ttl.toString());

    // to do with value removed
    // const G2_tmp1 = G.ctx.PAIR.G2mul(X1, a1);

    const G2_tmp2 = G.ctx.PAIR.G2mul(X2, a2);
    // const G2_tmp3 = G.ctx.PAIR.G2mul(X3, a3); // this is now provided as pkX
    const G2_tmp4 = G.ctx.PAIR.G2mul(X4, id);

    // so that the original key wouldn't be mutated
    const X0_cpy = new G.ctx.ECP2();

    X0_cpy.copy(X0);

    // to do with value
    // X0_cpy.add(G2_tmp1);

    X0_cpy.add(G2_tmp2);
    X0_cpy.add(pkX);
    X0_cpy.add(G2_tmp4);

    X0_cpy.affine();

    // for some reason sig1.x, sig1.y, sig2.x and sig2.y return false to being instances of FP when signed by SAs,
    // hence temporary, ugly hack:
    // I blame javascript pseudo-broken typesystem
    const tempX1 = new G.ctx.FP(0);
    const tempY1 = new G.ctx.FP(0);
    tempX1.copy(sig1.getx());
    tempY1.copy(sig1.gety());
    sig1.x = tempX1;
    sig1.y = tempY1;

    const tempX2 = new G.ctx.FP(0);
    const tempY2 = new G.ctx.FP(0);
    tempX2.copy(sig2.getx());
    tempY2.copy(sig2.gety());
    sig2.x = tempX2;
    sig2.y = tempY2;

    const Gt_1 = e(sig1, X0_cpy);
    const Gt_2 = e(sig2, g);

    return !sig2.INF && Gt_1.equals(Gt_2);
  }
}
