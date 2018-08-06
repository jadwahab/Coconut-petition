// A slightly modified Pointcheval-Sanders Short Randomizable Signatures scheme
// to allow for larger number of signed messages from multiple authorities

import BpGroup from './BpGroup';
import { ctx } from './globalConfig';
import { hashToBIG, hashG2ElemToBIG, hashToPointOnCurve, hashMessage } from './auxiliary';
import ElGamal from './ElGamal';

export default class CredSig {
  static setup() {
    const G = new BpGroup();

    const g1 = G.gen1;
    const g2 = G.gen2;
    const e = G.pair;
    const o = G.order;
    // create h to ge g1^p
    const p = new ctx.BIG(2);
    const h1 = G.ctx.PAIR.G1mul(g1, p);

    return [G, o, g1, g2, e, h1];
  }

  static keygen(params) {
    const [G, o, g1, g2, e] = params;

    const x = G.ctx.BIG.randomnum(G.order, G.rngGen);
    const y = G.ctx.BIG.randomnum(G.order, G.rngGen);

    const X = G.ctx.PAIR.G2mul(g2, x);
    const Y = G.ctx.PAIR.G2mul(g2, y);

    const sk = [x, y];
    const pk = [g2, X, Y];

    return [sk, pk];
  }

  // sig = (x + m*y) * h
  static sign(params, sk, coin_sk, coin_pk) {
    const [G, o, g1, g2, e] = params;
    const [x, y] = sk;

    const h = hashToPointOnCurve(coin_pk.toString());

    const m = new G.ctx.BIG(coin_sk);

    // calculate t1 = (y * m) mod p
    const t1 = G.ctx.BIG.mul(y, m);
    t1.mod(o);
    // x + t1
    const K = new G.ctx.BIG(t1);
    K.add(x);
    // K = (x + m*y) mod p
    K.mod(o);

    const sig = G.ctx.PAIR.G1mul(h, K);

    return [h, sig];
  }

  //  e(h, X + m*Y) == e(sig, g)
  static verify(params, pk, coin_sk, sigma) {
    // aggregation failed because h differed
    if (!sigma) {
      return false;
    }
    const [G, o, g1, g2, e] = params;
    const [g, X, Y] = pk;
    const [h, sig] = sigma;

    const expr = G.ctx.PAIR.G2mul(Y, coin_sk);
    expr.add(X);
    expr.affine();

    // for some reason h.x, h.y, sig.x and sig.y return false to being instances of FP when signed by SAs,
    // hence temporary, ugly hack:
    // I blame javascript pseudo-broken typesystem
    const tempX1 = new G.ctx.FP(0);
    const tempY1 = new G.ctx.FP(0);
    tempX1.copy(h.getx());
    tempY1.copy(h.gety());
    h.x = tempX1;
    h.y = tempY1;

    const tempX2 = new G.ctx.FP(0);
    const tempY2 = new G.ctx.FP(0);
    tempX2.copy(sig.getx());
    tempY2.copy(sig.gety());
    sig.x = tempX2;
    sig.y = tempY2;

    const Gt_1 = e(h, expr);
    const Gt_2 = e(sig, g);

    return !h.INF && Gt_1.equals(Gt_2);
  }

  static randomize(params, sigma) {
    const [G, o, g1, g2, e] = params;
    const [h, sig] = sigma;
    const t = G.ctx.BIG.randomnum(G.order, G.rngGen);

    return [G.ctx.PAIR.G1mul(h, t), G.ctx.PAIR.G1mul(sig, t)];
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

  // for threshold decryption
  static aggregateElGamalPublicKeys(params, pks) {
    const [G, o, g1, g2, e] = params;
    const aPk = new G.ctx.ECP();

    for (let i = 0; i < pks.length; i++) {
      if (i === 0) {
        aPk.copy(pks[i]);
      } else {
        aPk.add(pks[i]);
      }
    }
    aPk.affine();

    return aPk;
  }

  // array for servers (issuer or SA)
  static aggregatePublicKeys_array(params, pks) {
    const [G, o, g1, g2, e] = params;

    const ag = new G.ctx.ECP2();
    const aX = new G.ctx.ECP2();
    const aY = new G.ctx.ECP2();

    for (let i = 0; i < pks.length; i++) {
      const [g, X, Y] = pks[i];
      if (i === 0) {
        ag.copy(g);
        aX.copy(X);
        aY.copy(Y);
      } else {
        aX.add(X);
        aY.add(Y);
      }
    }
    aX.affine();
    aY.affine();

    return [ag, aX, aY];
  }

  // object for client
  static aggregatePublicKeys_obj(params, pks) {
    const [G, o, g1, g2, e] = params;

    // same as g2 so no need for this:
    // const ag = new G.ctx.ECP2();
    // const [g, X, Y] = pks[Object.keys(pks)[0]];
    // ag.copy(g);

    const aX = new ctx.ECP2();
    Object.entries(pks).forEach(([server, publicKey]) => {
      aX.add(publicKey[1]); // publicKey has structure [g, X0, X1, X2, X3, X4], so we access element at 4th index
    });
    aX.affine();

    const aY = new ctx.ECP2();
    Object.entries(pks).forEach(([server, publicKey]) => {
      aY.add(publicKey[2]); // publicKey has structure [g, X0, X1, X2, X3, X4], so we access element at 4th index
    });
    aY.affine();

    return [g2, aX, aY];
  }

  static verifyAggregation(params, pks, coin, aggregateSignature) {
    const aPk = CredSig.aggregatePublicKeys_array(params, pks);
    return CredSig.verify(params, aPk, coin, aggregateSignature);
  }

  // no need to pass h - encryption is already using it EDIT: make sure!
  static blindSignComponent(sk_component, encrypted_param) {
    const [encrypted_param_a, encrypted_param_b] = encrypted_param;
    const sig_a = ctx.PAIR.G1mul(encrypted_param_a, sk_component);
    const sig_b = ctx.PAIR.G1mul(encrypted_param_b, sk_component);

    return [sig_a, sig_b];
  }

  static mixedSignCoin(params, sk, signingCoin) {
    const [G, o, g1, g2, e] = params;
    const [x, y] = sk;

    const reducer = (acc, cur) => acc + cur;

    const coinStr =
      signingCoin.pk_client_bytes.reduce(reducer) + // 1- client's key
      signingCoin.pk_coin_bytes.reduce(reducer) + // 2- coin's pk
      signingCoin.issuedCoinSig[0].reduce(reducer) + // 3- (1 & 2) signed by issuer
      signingCoin.issuedCoinSig[1].reduce(reducer); // (1 & 2 & 3 & enc_sk) signed by client

    const h = hashToPointOnCurve(coinStr);

    // EDIT: change enc_sk to enc_commitment or something
    // c = (a, b)
    const enc_sk = [ctx.ECP.fromBytes(signingCoin.enc_sk_bytes[0]), ctx.ECP.fromBytes(signingCoin.enc_sk_bytes[1])];

    const [enc_param_a, enc_param_b] = enc_sk;
    // a' = y * a
    const enc_sig_a = ctx.PAIR.G1mul(enc_param_a, y);

    // x * h
    const temp = G.ctx.PAIR.G1mul(h, x);
    // y * b
    const enc_sig_b = ctx.PAIR.G1mul(enc_param_b, y);
    // b' = x*h + y*b
    enc_sig_b.add(temp);

    // c' = (y*a, x*h + y*b)
    enc_sig_a.affine();
    enc_sig_b.affine();

    // return [h, c']
    return [h, [enc_sig_a, enc_sig_b]];
  }

  static make_proof_credentials_petition(params, agg_vk, sigma, m, petitionOwner, petitionID) {
    const [G, o, g1, g2, e] = params;
    // const agg_vk = CredSig.aggregatePublicKeys_obj(params, signingAuthPubKeys); // agg_vk = [ag, aX, aY]

    // MATERIALS: rand t, kappa, nu, zeta
    const t = ctx.BIG.randomnum(G.order, G.rngGen);

    // kappa = t*g2 + aX + m*aY :
    const kappa = ctx.PAIR.G2mul(g2, t); // t*g2
    const aX = agg_vk[1]; // aX
    const aY = agg_vk[2]; // aY
    const pkY = ctx.PAIR.G2mul(aY, m); // m*Y
    kappa.add(aX);
    kappa.add(pkY);
    kappa.affine();

    const [h, sig] = sigma;

    // nu = t*h
    // EDIT: DEPENDS ON IF Cm USED G1 OR G2 in generateCoinSecret of CredentialRequester.js
    const nu = ctx.PAIR.G1mul(h, t);

    const gs = hashToPointOnCurve(petitionID);

    // zeta = m*gs
    const zeta = ctx.PAIR.G1mul(gs, m);

    // PROOF: pi_v
    // create witnesses
    const wm = ctx.BIG.randomnum(G.order, G.rngGen);
    const wt = ctx.BIG.randomnum(G.order, G.rngGen);

    // compute the witnesses commitments
    const Aw = ctx.PAIR.G2mul(g2, wt);
    Aw.add(aX);
    const pkYw = ctx.PAIR.G2mul(aY, wm);
    Aw.add(pkYw);
    Aw.affine();
    const Bw = ctx.PAIR.G1mul(h, wt);
    Bw.affine();
    const Cw = ctx.PAIR.G1mul(gs, wm);
    Cw.affine();

    // create the challenge
    const c = hashToBIG(g1.toString() + g2.toString() + aX.toString() + aY.toString()
      + Aw.toString() + Bw.toString() + Cw.toString() + petitionOwner.toString());

    // create responses
    const rm = new ctx.BIG(wm);
    const rt = new ctx.BIG(wt);

    // to prevent object mutation
    const m_cpy = new ctx.BIG(m);
    const t_cpy = new ctx.BIG(t);
    const c_cpy = new ctx.BIG(c);
    m_cpy.mod(o);
    t_cpy.mod(o);
    c_cpy.mod(o);

    const t1 = ctx.BIG.mul(m_cpy, c_cpy); // produces DBIG
    const t2 = t1.mod(o); // but this gives BIG back

    const t3 = ctx.BIG.mul(t_cpy, c_cpy); // produces DBIG
    const t4 = t3.mod(o); // but this gives BIG back

    wm.mod(o);
    wt.mod(o);

    rm.sub(t2);
    rm.add(o); // to ensure positive result
    rm.mod(o);

    rt.sub(t4);
    rt.add(o); // to ensure positive result
    rt.mod(o);

    const pi_v = {
      c: c,
      rm: rm,
      rt: rt
    };

    return [kappa, nu, zeta, pi_v];
  }

  static verify_proof_credentials_petition(params, agg_vk, sigma, MPCP_output, petitionOwner, petitionID) {
    if (!sigma) {
      return false;
    }
    const [G, o, g1, g2, e] = params;
    const [ag, aX, aY] = agg_vk;
    const [h, sig] = sigma;
    const [kappa, nu, zeta, pi_v] = MPCP_output;
    const c = pi_v.c;
    const rm = pi_v.rm;
    const rt = pi_v.rt;
    const gs = hashToPointOnCurve(petitionID);

    // re-compute the witness commitments
    const Aw = ctx.PAIR.G2mul(kappa, c);
    const temp1 = ctx.PAIR.G2mul(g2, rt);
    Aw.add(temp1);
    Aw.add(aX);
    const temp2 = ctx.PAIR.G2mul(aX, c);
    Aw.sub(temp2);
    const temp3 = ctx.PAIR.G2mul(aY, rm);
    Aw.add(temp3);
    Aw.affine();

    const Bw = ctx.PAIR.G1mul(nu, c);
    const temp4 = ctx.PAIR.G1mul(h, rt);
    Bw.add(temp4);
    Bw.affine();

    const Cw = ctx.PAIR.G1mul(gs, rm);
    const temp5 = ctx.PAIR.G1mul(zeta, c);
    Cw.add(temp5);
    Cw.affine();
    
    // BIG.comp(a,b): Compare a and b, return 0 if a==b, -1 if a<b, +1 if a>b
    const expr1 = ctx.BIG.comp(c, hashToBIG(g1.toString() + g2.toString() + aX.toString() + aY.toString()
    + Aw.toString() + Bw.toString() + Cw.toString() + petitionOwner.toString())) === 0;

    return (!h.INF && expr1);
  }

  static make_proof_vote_petition(params, pub, vote) {
    const [G, o, g1, g2, e, h1] = params;
    if (typeof vote === 'number') {
      vote = new ctx.BIG(vote);
    }
    const [a, b, k] = ElGamal.encrypt(params, pub, vote, h1);
    const enc_v = [a, b];
    
    const r1 = ctx.BIG.randomnum(G.order, G.rngGen);
    const r2 = new ctx.BIG(r1);
    const vote_cpy = new ctx.BIG(vote); // to prevent object mutation
    const t1 = ctx.BIG.mul(vote_cpy, r1); // produces DBIG
    const t2 = t1.mod(o); // but this gives BIG back
    r2.sub(t2);
    r2.add(o); // to ensure positive result
    r2.mod(o);

    const Cv = ctx.PAIR.G1mul(g1, vote);
    const temp4 = ctx.PAIR.G1mul(h1, r1);
    Cv.add(temp4);
    Cv.affine();

    // create random witnesses
    const wk = ctx.BIG.randomnum(G.order, G.rngGen);
    const wv = ctx.BIG.randomnum(G.order, G.rngGen);
    const wr1 = ctx.BIG.randomnum(G.order, G.rngGen);
    const wr2 = ctx.BIG.randomnum(G.order, G.rngGen);

    const Wa = ctx.PAIR.G1mul(g1, wk);
    Wa.affine();
    
    const Wb = ctx.PAIR.G1mul(pub, wk);
    const blind_factor = ctx.PAIR.G1mul(h1, wv);
    Wb.add(blind_factor);
    Wb.affine();
  
    const WCv = ctx.PAIR.G1mul(g1, wv);
    const blind_factor2 = ctx.PAIR.G1mul(h1, wr1);
    WCv.add(blind_factor2);
    WCv.affine();
    
    const WCv2 = ctx.PAIR.G1mul(Cv, wv);
    const blind_factor3 = ctx.PAIR.G1mul(h1, wr2);
    WCv2.add(blind_factor3);
    WCv2.affine();
  
    const C = hashToBIG(g1.toString() + h1.toString() + a.toString() + b.toString() +
      Cv.toString() + Wa.toString() + Wb.toString() + WCv.toString() + WCv2.toString());

    // to prevent object mutation
    const k_cpy = new ctx.BIG(k);
    const v_cpy = new ctx.BIG(vote);
    const r1_cpy = new ctx.BIG(r1);
    const r2_cpy = new ctx.BIG(r2);
    const C_cpy = new ctx.BIG(C);
    k_cpy.mod(o);
    v_cpy.mod(o);
    r1_cpy.mod(o);
    r2_cpy.mod(o);
    C_cpy.mod(o);

    // rk
    const tk1 = ctx.BIG.mul(k_cpy, C_cpy); // produces DBIG
    const tk2 = tk1.mod(o); // but this gives BIG back
    const rk = new ctx.BIG(wk);
    rk.sub(tk2);
    rk.add(o); // to ensure positive result
    rk.mod(o);
    
    // rv
    const tv1 = ctx.BIG.mul(v_cpy, C_cpy); // produces DBIG
    const tv2 = tv1.mod(o); // but this gives BIG back
    const rv = new ctx.BIG(wv);
    rv.sub(tv2);
    rv.add(o); // to ensure positive result
    rv.mod(o);

    // rr1
    const tr1_1 = ctx.BIG.mul(r1_cpy, C_cpy); // produces DBIG
    const tr1_2 = tr1_1.mod(o); // but this gives BIG back
    const rr1 = new ctx.BIG(wr1);
    rr1.sub(tr1_2);
    rr1.add(o); // to ensure positive result
    rr1.mod(o);

    // rr2
    const tr2_1 = ctx.BIG.mul(r2_cpy, C_cpy); // produces DBIG
    const tr2_2 = tr2_1.mod(o); // but this gives BIG back
    const rr2 = new ctx.BIG(wr2);
    rr2.sub(tr2_2);
    rr2.add(o); // to ensure positive result
    rr2.mod(o);

    return [enc_v, C, Cv, rk, rv, rr1, rr2];
  }

  static verify_proof_vote_petition(params, pub, MPVP_output) {
    const [G, o, g1, g2, e, h1] = params;
    const [enc_v, C, Cv, rk, rv, rr1, rr2] = MPVP_output;
    const [a, b] = enc_v;

    const Wa_prove = ctx.PAIR.G1mul(g1, rk);
    const tWa1 = ctx.PAIR.G1mul(a, C);
    Wa_prove.add(tWa1);
    Wa_prove.affine();
  
    const Wb_prove = ctx.PAIR.G1mul(pub, rk);
    const tWb1 = ctx.PAIR.G1mul(h1, rv);
    const tWb2 = ctx.PAIR.G1mul(b, C);
    Wb_prove.add(tWb1);
    Wb_prove.add(tWb2);
    Wb_prove.affine();

    const WCv_prove = ctx.PAIR.G1mul(g1, rv);
    const tWCv1 = ctx.PAIR.G1mul(h1, rr1);
    const tWCv2 = ctx.PAIR.G1mul(Cv, C);
    WCv_prove.add(tWCv1);
    WCv_prove.add(tWCv2);
    WCv_prove.affine();
    
    const WCv2_prove = ctx.PAIR.G1mul(Cv, rv);
    const tWCv2_1 = ctx.PAIR.G1mul(h1, rr2);
    const tWCv2_2 = ctx.PAIR.G1mul(Cv, C);
    WCv2_prove.add(tWCv2_1);
    WCv2_prove.add(tWCv2_2);
    WCv2_prove.affine();

    const C_prove = hashToBIG(g1.toString() + h1.toString() + a.toString() + b.toString() +
    Cv.toString() + Wa_prove.toString() + Wb_prove.toString() + WCv_prove.toString() + WCv2_prove.toString());
  
    const expr = ctx.BIG.comp(C, C_prove) === 0;
  
    return expr;
  }
}
