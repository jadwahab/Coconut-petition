// A slightly modified Pointcheval-Sanders Short Randomizable Signatures scheme
// to allow for larger number of signed messages from multiple authorities

import BpGroup from './BpGroup';
import { ctx } from '../src/config';
import { hashToBIG, hashG2ElemToBIG, hashToPointOnCurve, hashMessage } from './auxiliary';
import ElGamal from './ElGamal';

export default class CredSig {
  static setup() {
    const G = new BpGroup();

    const g1 = G.gen1;
    const g2 = G.gen2;
    const e = G.pair;
    const o = G.order;
    // create h to ge g1^power
    const p = new ctx.BIG(2);
    const h1 = G.ctx.PAIR.G1mul(g1, p);

    return [G, o, g1, g2, e, h1];
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
    const aPk = CredSig.aggregatePublicKeys(params, pks);
    return CredSig.verify(params, aPk, coin, aggregateSignature);
  }

  // no need to pass h - encryption is already using it EDIT: make sure!
  static blindSignComponent(sk_component, encrypted_param) {
    const [encrypted_param_a, encrypted_param_b] = encrypted_param;
    const sig_a = ctx.PAIR.G1mul(encrypted_param_a, sk_component);
    const sig_b = ctx.PAIR.G1mul(encrypted_param_b, sk_component);

    return [sig_a, sig_b];
  }

  static mixedSignCred(params, sk, signingCred) {
    const [G, o, g1, g2, e] = params;
    const [x, y] = sk;

    const reducer = (acc, cur) => acc + cur;

    const coinStr =
      signingCred.pk_client_bytes.reduce(reducer) + // 1- client's key
      signingCred.pk_coin_bytes.reduce(reducer) + // 2- coin's pk
      signingCred.issuedCredSig[0].reduce(reducer) + // 3- (1 & 2) signed by issuer
      signingCred.issuedCredSig[1].reduce(reducer); // (1 & 2 & 3 & enc_sk) signed by client

    const h = hashToPointOnCurve(coinStr);

    // EDIT: change enc_sk to enc_commitment or something
    // c = (a, b)
    const enc_sk = [ctx.ECP.fromBytes(signingCred.enc_sk_bytes[0]), ctx.ECP.fromBytes(signingCred.enc_sk_bytes[1])];

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
    // EDIT: DEPENDS ON IF Cm USED G1 OR G2 in generateCredSecret of CredentialRequester.js
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
}
