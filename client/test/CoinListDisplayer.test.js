import React from 'react';
import { expect } from 'chai';
import { before } from 'mocha';
import { shallow, mount, render } from 'enzyme';
import CoinDisplayer from '../src/components/CoinDisplayer';
import MainView from '../src/components/MainView';
import CoinListDisplayer from '../src/components/CoinListDisplayer';
import CredentialRequester from '../src/components/CredentialRequester';

let coinListDisplayerNode;

describe('CoinListDisplayer Component', () => {
  let wrapper;
  before(async () => {
    wrapper = mount(<MainView />);
    await wrapper.find(CredentialRequester).at(0).props().handleCoinSubmit(212);
    await wrapper.find(CredentialRequester).at(0).props().handleCoinSubmit(213);
    wrapper.update();
    coinListDisplayerNode = wrapper.find(CoinListDisplayer);
  });

  it('Should have received array of coin objects', () => {
    expect(coinListDisplayerNode.props().coins).to.be.an('Array').to.not.be.empty;
    expect(coinListDisplayerNode.props().coins[0]).to.be.an('object').to.not.be.empty;
    expect(coinListDisplayerNode.props().coins[1]).to.be.an('object').to.not.be.empty;
  });

  it('Contains as many CoinDisplayer children as it got coin objects in props', () => {
    const coinDisplayerNodes = wrapper.find(CoinDisplayer);
    expect(coinDisplayerNodes).to.have.length(2);

    const wrapper2 = mount(<CoinListDisplayer coins={[]} />);
    const coinDisplayerNodes2 = wrapper2.find(CoinDisplayer);
    expect(coinDisplayerNodes2).to.have.length(0);

    const wrapper3 = mount(<CoinListDisplayer coins={[{ sk: {}, coin: {} }]} />);
    const coinDisplayerNodes3 = wrapper3.find(CoinDisplayer);
    expect(coinDisplayerNodes3).to.have.length(1);
  });
});
