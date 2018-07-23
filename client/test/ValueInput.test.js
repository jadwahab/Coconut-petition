import React from 'react';
import { expect } from 'chai';
import { shallow, mount, render } from 'enzyme';
import ValueInput from '../src/components/ValueInput';
import CredentialRequester from '../src/components/CredentialRequester';

describe('ValueInput Component', () => {
  describe("Upon receiving invalid, non-integer input, it sets it's isInputValid state to false", () => {
    it('Upon receiving a string input', () => {
      const wrapper = mount(<ValueInput
        onInputChange={() => {}}
      />);
      const input = wrapper.find('input');

      input.simulate('change', { target: { value: 'test' } });
      expect(wrapper.state('isInputValid')).to.equal(false);
    });

    it('Upon receiving a float number input', () => {
      const wrapper = mount(<ValueInput
        onInputChange={() => {}}
      />);
      const input = wrapper.find('input');

      input.simulate('change', { target: { value: '42.2' } });
      expect(wrapper.state('isInputValid')).to.equal(false);
    });
  });

  it("Upon receiving a valid, integer, input, it sets it's isInputValid state to true", () => {
    const wrapper = mount(<ValueInput
      onInputChange={() => {}}
    />);
    const input = wrapper.find('input');

    input.simulate('change', { target: { value: '42' } });
    expect(wrapper.state('isInputValid')).to.equal(true);

    input.simulate('change', { target: { value: '42.00' } }); // it still equals to '42'
    expect(wrapper.state('isInputValid')).to.equal(true);
  });


  it('Should have received "onInputChange" function as a prop', () => {
    const mainWrapper = mount(<CredentialRequester />);
    const wrapper = mainWrapper.find(ValueInput);
    expect(wrapper.props().onInputChange).to.be.a('Function');
  });
});
