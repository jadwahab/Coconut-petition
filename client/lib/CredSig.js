// A slightly modified Pointcheval-Sanders Short Randomizable Signatures scheme
// to allow for larger number of signed messages from multiple authorities

import BpGroup from './BpGroup';
import { ctx } from '../src/config';
import { hashToBIG, hashG2ElemToBIG, hashToPointOnCurve, hashMessage } from './Proofs';
import ElGamal from './ElGamal';

export default class CredSig {
  static setup() {
    const G = new BpGroup();

    const g1 = G.gen1;
    const g2 = G.gen2;
    const e = G.pair;
    const o = G.order;
    // create h to ge g1^p
    // h('h1') -> like gs
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

  static verifyAggregation(params, pks, cred, aggregateSignature) {
    const aPk = CredSig.aggregatePublicKeys(params, pks);
    return CredSig.verify(params, aPk, cred, aggregateSignature);
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

    const credStr =
      signingCred.pk_client_bytes.reduce(reducer) + // 1- client's key
      signingCred.pk_cred_bytes.reduce(reducer) + // 2- cred's pk
      signingCred.issuedCredSig[0].reduce(reducer) + // 3- (1 & 2) signed by issuer
      signingCred.issuedCredSig[1].reduce(reducer); // (1 & 2 & 3 & enc_sk) signed by client

    const h = hashToPointOnCurve(credStr);

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
}