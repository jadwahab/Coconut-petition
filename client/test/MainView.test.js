import React from 'react';
import { expect, assert } from 'chai';
import { shallow, mount, render } from 'enzyme';
import MainView from '../src/components/MainView';
import CredentialRequester from '../src/components/CredentialRequester';
import VoteListDisplayer from '../src/components/VoteListDisplayer';
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

  it('Has mounted VoteListDisplayer', () => {
    const wrapper = mount(<MainView />);
    expect(wrapper.find(VoteListDisplayer)).to.have.length(1);
  });

  it('Has initially empty array for creds state', () => {
    const wrapper = mount(<MainView />);
    expect(wrapper.state().creds).to.be.an('Array').that.is.empty;
  });

  describe('Coin generation', async () => {
    const credValue = 42;
    const wrapper = mount(<MainView />);
    const input = wrapper.find(CredentialRequester).find('input');
    // input value
    input.simulate('change', { target: { value: credValue } });

    // submit value
    const button = wrapper.find(CredentialRequester).find('button');
    button.simulate('click');

    await wait(200);

    it('Upon submitting cred of given value, the Coin object has that value', () => {
      expect(wrapper.state('creds')[0].cred.value).to.equal(credValue);
    });

    it("Coin's PK = g2^SK", () => {
      const [G, o, g1, g2, e] = params;
      const { sk } = wrapper.state('creds')[0];
      const pk = wrapper.state('creds')[0].cred.v;

      assert.isTrue(pk.equals(G.ctx.PAIR.G2mul(g2, sk)));
    });
  });
});
