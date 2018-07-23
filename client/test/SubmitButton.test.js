import React from 'react';
import { expect } from 'chai';
import { shallow, mount, render } from 'enzyme';
import sinon from 'sinon';
import { Button } from 'semantic-ui-react';
import SubmitButton from '../src/components/SubmitButton';
import CredentialRequester from '../src/components/CredentialRequester';


describe('SubmitButton Component', () => {
  it('Should have received "onSubmit" function as a prop', () => {
    const mainWrapper = mount(<CredentialRequester />);
    const wrapper = mainWrapper.find(SubmitButton);
    expect(wrapper.props().onSubmit).to.be.a('Function');
  });

  it('Should have received "isDisabled" boolean as a prop', () => {
    const mainWrapper = mount(<CredentialRequester />);
    const wrapper = mainWrapper.find(SubmitButton);
    expect(wrapper.props().isDisabled).to.be.a('boolean');
  });

  it('The "disabled" attribute of the button should be the same one as received in props', () => {
    const wrapper = mount(<SubmitButton isDisabled={true} />);
    const buttonNode = wrapper.find(Button);
    expect(buttonNode.props().disabled).to.be.a('boolean').to.equal(true);

    const wrapper2 = mount(<SubmitButton isDisabled={false} />);
    const buttonNode2 = wrapper2.find(Button);
    expect(buttonNode2.props().disabled).to.be.a('boolean').to.equal(false);
  });

  it('Should call "handleCoinSubmit" sent from CredentialRequester Component when there is a valid value in input field', () => {
    const callback = sinon.spy();
    const mainWrapper = mount(<CredentialRequester handleCoinSubmit={callback} />);

    mainWrapper.find('input').simulate('change', { target: { value: '42' } });
    mainWrapper.find('button').simulate('click');

    expect(callback.calledOnce).to.equal(true);
  });
});
