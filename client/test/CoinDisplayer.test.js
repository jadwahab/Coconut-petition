import React from 'react';
import { assert, expect } from 'chai';
import { before } from 'mocha';
import sinon from 'sinon';
import { shallow, mount, render } from 'enzyme';
import VoteDisplayer from '../src/components/VoteDisplayer';
import CoinActionButton from '../src/components/CoinActionButton';
import MainView from '../src/components/MainView';
import { params, COIN_STATUS, signingServers, issuer, ctx } from '../src/config';
import CoinSig from '../lib/CoinSig';
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
  const coinValue = 42;
  before(async () => {
    const wrapper = mount(<MainView />);
    wrapper.find('input').simulate('change', { target: { value: coinValue } });
    await wrapper.find(CredentialRequester).at(0).props().handleCoinSubmit(coinValue);

    wrapper.update();
    VoteDisplayerNode = wrapper.find(VoteDisplayer);
    requestedCoin = VoteDisplayerNode.props().coin;
  });
  describe('Should have received Coin as a prop', () => {
    it('That has TTL in a future', () => {
      expect(VoteDisplayerNode.props().coin.ttl > new Date().getTime()).to.equal(true);
    });

    it('That has the same value as from the input', () => {
      expect(VoteDisplayerNode.props().coin.value).to.equal(coinValue);
    });
  });

  describe('CoinActionButton child behaviour', () => {
    it('Has CoinActionButton child component', () => {
      const wrapper = mount(<VoteDisplayer coin={requestedCoin} sk={null} id={null} ElGamalPK={null} ElGamalSK={null} sk_client={null} />);

      expect(VoteDisplayerNode.find(CoinActionButton)).to.have.length(1);
    });

    it('If VoteDisplayer has coinState "Generated", CoinActionButton will call "handleCoinSign" on click', () => {
      const wrapper = mount(<VoteDisplayer coin={requestedCoin} />);
      wrapper.setState({ coinState: COIN_STATUS.created });
      const spy = sinon.spy(wrapper.instance(), 'handleCoinSign');

      wrapper.instance().forceUpdate();

      wrapper.find('button').simulate('click');
      expect(spy.calledOnce).to.equal(true);
    });

    it('If VoteDisplayer has coinState "Signed", CoinActionButton will call "handleCoinSpend" on click', () => {
      const wrapper = mount(<VoteDisplayer coin={requestedCoin} />);
      wrapper.setState({ coinState: COIN_STATUS.signed });
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

      const [coin_sk, coin_pk] = generateCoinSecret();
      const [coin, id] = await getCoin(
        coin_sk,
        coin_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        coin={coin}
        sk={coin_sk}
        id={id}
        ElGamalSK={sk_elgamal}
        ElGamalPK={pk_elgamal}
        sk_client={skBytes_client}
      />);

      const signatures = await wrapper.instance().getSignatures(signingServers);
      const publicKeys = await Promise.all(signingServers.map(async server => getSigningAuthorityPublicKey(server)));

      for (let i = 0; i < signatures.length; i++) {
        const pkX = ctx.PAIR.G2mul(publicKeys[i][4], coin_sk);
        expect(CoinSig.verifyMixedBlindSign(params, publicKeys[i], coin, signatures[i], id, pkX)).to.equal(true);
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

      const [coin_sk, coin_pk] = generateCoinSecret();
      const [coin, id] = await getCoin(
        coin_sk,
        coin_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        coin={coin}
        sk={coin_sk}
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

      const [coin_sk, coin_pk] = generateCoinSecret();
      const [coin, id] = await getCoin(
        coin_sk,
        coin_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        coin={coin}
        sk={coin_sk}
        id={id}
        ElGamalSK={sk_elgamal}
        ElGamalPK={pk_elgamal}
        sk_client={skBytes_client}
      />);

      const signatures = await wrapper.instance().getSignatures(signingServers);
      const publicKeys = await Promise.all(signingServers.map(async server => getSigningAuthorityPublicKey(server)));

      const aggregatePublicKey = CoinSig.aggregatePublicKeys(params, publicKeys);

      wrapper.instance().aggregateAndRandomizeSignatures(signatures);
      assert.isNotNull(wrapper.state('randomizedSignature'));

      const pkX = ctx.PAIR.G2mul(aggregatePublicKey[4], coin_sk);
      expect(CoinSig.verifyMixedBlindSign(params, aggregatePublicKey, coin, wrapper.state('randomizedSignature'), id, pkX)).to.equal(true);
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

      const [coin_sk, coin_pk] = generateCoinSecret();
      const [coin, id] = await getCoin(
        coin_sk,
        coin_pk,
        42,
        pkBytes_client,
        skBytes_client,
        issuer,
      );

      const wrapper = mount(<VoteDisplayer
        key={id}
        coin={coin}
        sk={coin_sk}
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
