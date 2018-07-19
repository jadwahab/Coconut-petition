import React from 'react';
import { expect } from 'chai';
import { shallow, mount, render } from 'enzyme';
import ValueInput from '../src/components/ValueInput';
import SubmitButton from '../src/components/SubmitButton';
import CoinRequester from '../src/components/CoinRequester';
import MainView from '../src/components/MainView';

describe('CoinRequester Component', () => {
  it('Contains a ValueInput component', () => {
    const wrapper = mount(<CoinRequester />);
    expect(wrapper.find(ValueInput)).to.have.length(1);
  });

  it('Contains a SubmitButton component', () => {
    const wrapper = mount(<CoinRequester />);
    expect(wrapper.find(SubmitButton)).to.have.length(1);
  });

  it('Should have initial value state of 0', () => {
    const wrapper = mount(<CoinRequester />);
    expect(wrapper.state().value).to.equal(0);
  });

  it('Should have initial isRequesting state of false', () => {
    const wrapper = mount(<CoinRequester />);
    expect(wrapper.state().isRequesting).to.equal(false);
  });

  it('Should have received "handleCoinSubmit" function as a prop', () => {
    const mainWrapper = mount(<MainView />);
    const wrapper = mainWrapper.find(CoinRequester);
    expect(wrapper.props().handleCoinSubmit).to.be.a('Function');
  });

  it('On input change, the value state is set to that value', () => {
    const wrapper = mount(<CoinRequester />);
    const input = wrapper.find('input');

    input.simulate('change', { target: { value: 2 } });
    expect(wrapper.state('value')).to.equal(2);
    input.simulate('change', { target: { value: 3 } });
    expect(wrapper.state('value')).to.equal(3);
  });

  it('On submitting input, the value state is still correctly set to that value', () => {
    const value = 42;
    // the behaviour of passed function is irrelevant for this component's state
    const wrapper = mount(<CoinRequester handleCoinSubmit={() => { }} />);
    const input = wrapper.find('input');

    // input value
    input.simulate('change', { target: { value } });

    // submit value
    const button = wrapper.find('button');
    button.simulate('click');

    expect(wrapper.state('value')).to.equal(value);
  });
});
