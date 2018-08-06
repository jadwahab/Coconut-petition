import React from 'react';
import { assert, expect } from 'chai';
import { before } from 'mocha';
import sinon from 'sinon';
import { shallow, mount, render } from 'enzyme';
import VoteDisplayer from '../src/components/VoteDisplayer';
import VoteActionButton from '../src/components/VoteActionButton';
import MainView from '../src/components/MainView';
import { params, CRED_STATUS, signingServers, issuer, ctx } from '../src/config';
import CredSig from '../lib/CredSig';
import { getSigningAuthorityPublicKey, getCoin } from '../src/utils/api';

import CredentialRequester from '../src/components/CredentialRequester';
import ElGamal from '../lib/ElGamal';

let VoteDisplayerNode;
let requestedCoin;

const generateCoinSecret = () => {
  const [G, o, g1, g2, e] = params;
  const sk = ctx.BIG.randomnum(G.order, G.rngGen);
  const pk = ctx.PAIR.G2mul(g2, sk);
  return [sk, pk];
};

describe('VoteDisplayer Component', async () => {
  const credValue = 42;
  before(async () => {
    const wrapper = mount(<MainView />);
    wrapper.find('input').simulate('change', { target: { value: credValue } });
    await wrapper.find(CredentialRequester).at(0).props().handleCoinSubmit(credValue);

    wrapper.update();
    VoteDisplayerNode = wrapper.find(VoteDisplayer);
    requestedCoin = VoteDisplayerNode.props().cred;
  });
  describe('Should have received Coin as a prop', () => {
    it('That has TTL in a future', () => {
      expect(VoteDisplayerNode.props().cred.ttl > new Date().getTime()).to.equal(true);
    });

    it('That has the same value as from the input', () => {
      expect(VoteDisplayerNode.props().cred.value).to.equal(credValue);
    });
  });

  describe('VoteActionButton child behaviour', () => {
    it('Has VoteActionButton child component', () => {
      const wrapper = mount(<VoteDisplayer cred={requestedCoin} sk={null} id={null} ElGamalPK={null} ElGamalSK={null} sk_client={null} />);

      expect(VoteDisplayerNode.find(VoteActionButton)).to.have.length(1);
    });

    it('If VoteDisplayer has credState "Generated", VoteActionButton will call "handleCoinSign" on click', () => {
      const wrapper = mount(<VoteDisplayer cred={requestedCoin} />);
      wrapper.setState({ credState: CRED_STATUS.created });
      const spy = sinon.spy(wrapper.instance(), 'handleCoinSign');

      wrapper.instance().forceUpdate();

      wrapper.find('button').simulate('click');
      expect(spy.calledOnce).to.equal(true);
    });

    it('If VoteDisplayer has credState "Signed", VoteActionButton will call "handleCoinSpend" on click', () => {
      const wrapper = mount(<VoteDisplayer cred={requestedCoin} />);
      wrapper.setState({ credState: CRED_STATUS.signed });
      const spy = sinon.spy(wrapper.instance(), 'handleCoinSpend');

      wrapper.instance().forceUpdate();

      wrapper.find('button').simulate('click');
      expect(spy.calledOnce).to.equal(true);
    });
  });

  describe('getSignatures method (REQUIRES SERVERS SPECIFIED IN config.js TO BE UP)', () => {
    it('Gets valid signatures from all alive signingServers', async () => {
      const [G, o, g1, g2, e] = params;

      const [sk_elgamal, pk_elgamal] = ElGamal.keygen(params);
      const skBytes_client = [];
      const pkBytes_client = [];
      const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
      sk_client.toBytes(skBytes_client);
      const pk_client = g1.mul(sk_client);
      pk_client.toBytes(pkBytes_client);

      const [cred_sk, cred_pk] = generateCoinSecret();
      const [cred, id] = await getCoin(
        cred_sk,
        cred_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        cred={cred}
        sk={cred_sk}
        id={id}
        ElGamalSK={sk_elgamal}
        ElGamalPK={pk_elgamal}
        sk_client={skBytes_client}
      />);

      const signatures = await wrapper.instance().getSignatures(signingServers);
      const publicKeys = await Promise.all(signingServers.map(async server => getSigningAuthorityPublicKey(server)));

      for (let i = 0; i < signatures.length; i++) {
        const pkX = ctx.PAIR.G2mul(publicKeys[i][4], cred_sk);
        expect(CredSig.verifyMixedBlindSign(params, publicKeys[i], cred, signatures[i], id, pkX)).to.equal(true);
      }
    });

    it('Gets null if one of requests produced an error (such is if server was down)', async () => {
      const invalidServers = signingServers.slice();
      invalidServers.push('127.0.0.1:3645');

      const [G, o, g1, g2, e] = params;

      const [sk_elgamal, pk_elgamal] = ElGamal.keygen(params);
      const skBytes_client = [];
      const pkBytes_client = [];
      const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
      sk_client.toBytes(skBytes_client);
      const pk_client = g1.mul(sk_client);
      pk_client.toBytes(pkBytes_client);

      const [cred_sk, cred_pk] = generateCoinSecret();
      const [cred, id] = await getCoin(
        cred_sk,
        cred_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        cred={cred}
        sk={cred_sk}
        id={id}
        ElGamalSK={sk_elgamal}
        ElGamalPK={pk_elgamal}
        sk_client={skBytes_client}
      />);

      const signatures = await wrapper.instance().getSignatures(invalidServers);

      assert.isNull(signatures[signatures.length - 1]);
    });
  });

  describe('aggregateAndRandomizeSignatures method (REQUIRES SERVERS SPECIFIED IN config.js TO BE UP)', () => {
    it('Produces a valid randomized, aggregate signature and sets state appropriately', async () => {
      const [G, o, g1, g2, e] = params;

      const [sk_elgamal, pk_elgamal] = ElGamal.keygen(params);
      const skBytes_client = [];
      const pkBytes_client = [];
      const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
      sk_client.toBytes(skBytes_client);
      const pk_client = g1.mul(sk_client);
      pk_client.toBytes(pkBytes_client);

      const [cred_sk, cred_pk] = generateCoinSecret();
      const [cred, id] = await getCoin(
        cred_sk,
        cred_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        cred={cred}
        sk={cred_sk}
        id={id}
        ElGamalSK={sk_elgamal}
        ElGamalPK={pk_elgamal}
        sk_client={skBytes_client}
      />);

      const signatures = await wrapper.instance().getSignatures(signingServers);
      const publicKeys = await Promise.all(signingServers.map(async server => getSigningAuthorityPublicKey(server)));

      const aggregatePublicKey = CredSig.aggregatePublicKeys(params, publicKeys);

      wrapper.instance().aggregateAndRandomizeSignatures(signatures);
      assert.isNotNull(wrapper.state('randomizedSignature'));

      const pkX = ctx.PAIR.G2mul(aggregatePublicKey[4], cred_sk);
      expect(CredSig.verifyMixedBlindSign(params, aggregatePublicKey, cred, wrapper.state('randomizedSignature'), id, pkX)).to.equal(true);
    });

    it("If one of signatures was null, aggregate won't be created and state will be set appropriately", async () => {
      const invalidServers = signingServers.slice();
      invalidServers.push('127.0.0.1:8451');
      const [G, o, g1, g2, e] = params;

      const [sk_elgamal, pk_elgamal] = ElGamal.keygen(params);
      const skBytes_client = [];
      const pkBytes_client = [];
      const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
      sk_client.toBytes(skBytes_client);
      const pk_client = g1.mul(sk_client);
      pk_client.toBytes(pkBytes_client);

      const [cred_sk, cred_pk] = generateCoinSecret();
      const [cred, id] = await getCoin(
        cred_sk,
        cred_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        cred={cred}
        sk={cred_sk}
        id={id}
        ElGamalSK={sk_elgamal}
        ElGamalPK={pk_elgamal}
        sk_client={skBytes_client}
      />);

      const signatures = await wrapper.instance().getSignatures(invalidServers);
      wrapper.instance().aggregateAndRandomizeSignatures(signatures);

      assert.isNull(wrapper.state('randomizedSignature'));
    });
  });
});
