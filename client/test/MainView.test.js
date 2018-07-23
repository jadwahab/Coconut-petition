import React from 'react';
import { expect, assert } from 'chai';
import { shallow, mount, render } from 'enzyme';
import MainView from '../src/components/MainView';
import CredentialRequester from '../src/components/CredentialRequester';
import CoinListDisplayer from '../src/components/CoinListDisplayer';
import { params } from '../src/config';
import { wait } from '../src/utils/api';

describe('MainView Component', () => {
  it('Has a single Grid Child', () => {
    const wrapper = mount(<MainView />);
    expect(wrapper.children().length).to.equal(1);
  });

  it('Has mounted CredentialRequester', () => {
    const wrapper = mount(<MainView />);
    expect(wrapper.find(CredentialRequester)).to.have.length(1);
  });

  it('Has mounted CoinListDisplayer', () => {
    const wrapper = mount(<MainView />);
    expect(wrapper.find(CoinListDisplayer)).to.have.length(1);
  });

  it('Has initially empty array for coins state', () => {
    const wrapper = mount(<MainView />);
    expect(wrapper.state().coins).to.be.an('Array').that.is.empty;
  });

  describe('Coin generation', async () => {
    const coinValue = 42;
    const wrapper = mount(<MainView />);
    const input = wrapper.find(CredentialRequester).find('input');
    // input value
    input.simulate('change', { target: { value: coinValue } });

    // submit value
    const button = wrapper.find(CredentialRequester).find('button');
    button.simulate('click');

    await wait(200);

    it('Upon submitting coin of given value, the Coin object has that value', () => {
      expect(wrapper.state('coins')[0].coin.value).to.equal(coinValue);
    });

    it("Coin's PK = g2^SK", () => {
      const [G, o, g1, g2, e] = params;
      const { sk } = wrapper.state('coins')[0];
      const pk = wrapper.state('coins')[0].coin.v;

      assert.isTrue(pk.equals(G.ctx.PAIR.G2mul(g2, sk)));
    });
  });
});
