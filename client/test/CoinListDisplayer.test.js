import React from 'react';
import { expect } from 'chai';
import { before } from 'mocha';
import { shallow, mount, render } from 'enzyme';
import VoteDisplayer from '../src/components/VoteDisplayer';
import MainView from '../src/components/MainView';
import VoteListDisplayer from '../src/components/VoteListDisplayer';
import CredentialRequester from '../src/components/CredentialRequester';

let VoteListDisplayerNode;

describe('VoteListDisplayer Component', () => {
  let wrapper;
  before(async () => {
    wrapper = mount(<MainView />);
    await wrapper.find(CredentialRequester).at(0).props().handleCoinSubmit(212);
    await wrapper.find(CredentialRequester).at(0).props().handleCoinSubmit(213);
    wrapper.update();
    VoteListDisplayerNode = wrapper.find(VoteListDisplayer);
  });

  it('Should have received array of coin objects', () => {
    expect(VoteListDisplayerNode.props().coins).to.be.an('Array').to.not.be.empty;
    expect(VoteListDisplayerNode.props().coins[0]).to.be.an('object').to.not.be.empty;
    expect(VoteListDisplayerNode.props().coins[1]).to.be.an('object').to.not.be.empty;
  });

  it('Contains as many VoteDisplayer children as it got coin objects in props', () => {
    const VoteDisplayerNodes = wrapper.find(VoteDisplayer);
    expect(VoteDisplayerNodes).to.have.length(2);

    const wrapper2 = mount(<VoteListDisplayer coins={[]} />);
    const VoteDisplayerNodes2 = wrapper2.find(VoteDisplayer);
    expect(VoteDisplayerNodes2).to.have.length(0);

    const wrapper3 = mount(<VoteListDisplayer coins={[{ sk: {}, coin: {} }]} />);
    const VoteDisplayerNodes3 = wrapper3.find(VoteDisplayer);
    expect(VoteDisplayerNodes3).to.have.length(1);
  });
});
