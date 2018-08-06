//
// After the Coin class was split into multiple files depending on cred's state, this tests are no longer applicable
//
// import { expect, assert } from 'chai';
// import { before } from 'mocha';
// import * as crypto from 'crypto';
// import Coin from '../lib/Coin';
// import CredSig from '../lib/CredSig'; // for params
// import { ctx } from '../src/config';
// import { getRandomCoinId } from '../src/utils/credGenerator';
// import ElGamal from '../lib/ElGamal';
//
// describe('Coin object', () => {
//   let credValue;
//   let v;
//   let cred;
//   let ide;
//   let g1;
//   before(() => {
//     credValue = 42;
//     v = { Dummy: 'object' };
//
//     g1 = new ctx.ECP();
//     const x = new ctx.BIG(0);
//     const y = new ctx.BIG(0);
//
//     x.rcopy(ctx.ROM_CURVE.CURVE_Gx);
//     y.rcopy(ctx.ROM_CURVE.CURVE_Gy);
//     g1.setxy(x, y);
//
//     const RAW = crypto.randomBytes(128);
//
//     const rng = new ctx.RAND();
//     rng.clean();
//     rng.seed(RAW.length, RAW);
//     const groupOrder = new ctx.BIG(0);
//     groupOrder.rcopy(ctx.ROM_CURVE.CURVE_Order);
//
//     ide = ctx.BIG.randomnum(groupOrder, rng);
//
//     cred = new Coin(v, ide, credValue);
//   });
//
//   describe('Construction', () => {
//     it('Coin ID equals to g1 to power of the random exponent', () => {
//       assert.isTrue(cred.ID.equals(ctx.PAIR.G1mul(g1, ide)));
//     });
//   });
//
//   it('The alias for getting public key works correctly', () => {
//     expect(cred.publicKey).to.equal(cred.v);
//   });
//
//   it('The alias for getting time to live works correctly', () => {
//     expect(cred.timeToLive).to.equal(cred.ttl);
//   });
//
//   // assumes previous tests would have detected errors so normal key generation could be used
//   describe('Prepare cred for signing', () => {
//     let properCoin;
//     let params;
//     let cred_sk;
//     let cred_pk;
//     let id;
//     before(() => {
//       const properCoinValue = 42;
//       params = CredSig.setup();
//       [cred_sk, cred_pk] = Coin.keygen(params);
//       id = getRandomCoinId();
//       properCoin = new Coin(cred_pk, id, properCoinValue);
//     });
//
//     it('Can prepare a cred', () => {
//       const [ElGamalSK, ElGamalPK] = ElGamal.keygen(params);
//       const signingCoin = properCoin.prepareCoinForSigning(ElGamalPK, params, id, cred_sk);
//
//       expect(signingCoin).to.have.property('bytesV').that.is.an('array');
//       expect(signingCoin).to.have.property('value').that.is.an('number');
//       expect(signingCoin).to.have.property('ttl').that.is.an('number');
//       expect(signingCoin).to.have.property('bytesID').that.is.an('array');
//       expect(signingCoin).to.have.property('enc_sk_bytes').that.is.an('array');
//       expect(signingCoin.enc_sk_bytes[0]).to.be.an('array');
//       expect(signingCoin.enc_sk_bytes[1]).to.be.an('array');
//       expect(signingCoin).to.have.property('enc_id_bytes').that.is.an('array')
//       expect(signingCoin.enc_id_bytes[0]).to.be.an('array');
//       expect(signingCoin.enc_id_bytes[1]).to.be.an('array');
//     });
//
//     it('Does not need all parameters if it is prepared for second time', () => {
//       const [ElGamalSK, ElGamalPK] = ElGamal.keygen(params);
//       const signingCoin = properCoin.prepareCoinForSigning(); // no parameters passed
//
//       expect(signingCoin).to.have.property('bytesV').that.is.an('array');
//       expect(signingCoin).to.have.property('value').that.is.an('number');
//       expect(signingCoin).to.have.property('ttl').that.is.an('number');
//       expect(signingCoin).to.have.property('bytesID').that.is.an('array');
//       expect(signingCoin).to.have.property('enc_sk_bytes').that.is.an('array');
//       expect(signingCoin.enc_sk_bytes[0]).to.be.an('array');
//       expect(signingCoin.enc_sk_bytes[1]).to.be.an('array');
//       expect(signingCoin).to.have.property('enc_id_bytes').that.is.an('array')
//       expect(signingCoin.enc_id_bytes[0]).to.be.an('array');
//       expect(signingCoin.enc_id_bytes[1]).to.be.an('array');
//     });
//
//     it('Can re-create Coin', () => {
//       const v_old = properCoin.v;
//       const value_old = properCoin.value;
//       const ttl_old = properCoin.ttl;
//       const ID_old = properCoin.ID;
//       const enc_sk_old = properCoin.enc_sk;
//       const enc_id_old = properCoin.enc_id;
//
//       const signingCoin = properCoin.prepareCoinForSigning();
//       const recreatedCoin = Coin.fromSigningCoin(signingCoin);
//
//       const v_new = recreatedCoin.v;
//       const value_new = recreatedCoin.value;
//       const ttl_new = recreatedCoin.ttl;
//       const ID_new = recreatedCoin.ID;
//       const enc_sk_new = recreatedCoin.enc_sk;
//       const enc_id_new = recreatedCoin.enc_id;
//
//       assert.isTrue(v_old.equals(v_new));
//       assert.isTrue(value_old === value_new);
//       assert.isTrue(ttl_old === ttl_new);
//       assert.isTrue(ID_old.equals(ID_new));
//       assert.isTrue(enc_sk_old[0].equals(enc_sk_new[0]));
//       assert.isTrue(enc_sk_old[1].equals(enc_sk_new[1]));
//       assert.isTrue(enc_id_old[0].equals(enc_id_new[0]));
//       assert.isTrue(enc_id_old[1].equals(enc_id_new[1]));
//     });
//   });
// });
