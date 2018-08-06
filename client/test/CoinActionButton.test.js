import React from 'react';
import { expect, assert } from 'chai';
import { shallow, mount, render } from 'enzyme';
import { Button } from 'semantic-ui-react';
import VoteDisplayer from '../src/components/VoteDisplayer';
import VoteActionButton from '../src/components/VoteActionButton';
import { COIN_STATUS } from '../src/config';

describe('VoteActionButton Component', () => {
  // save time by not generating entire object that we do not need anyway
  const dummyCoin = {
    cred: {
      ttl: new Date().getTime(),
      value: 42,
    },
  };

  it('Should have received "onSign" function as a prop', () => {
    const mainWrapper = mount(<VoteDisplayer
      cred={dummyCoin}
      sk={{ dummy: 'value' }}
      id={{ dummy: 'value' }}
      ElGamalPK={{ dummy: 'value' }}
      ElGamalSK={{ dummy: 'value' }}
      sk_client={[]}
    />);
    const wrapper = mainWrapper.find(VoteActionButton);
    expect(wrapper.props().onSign).to.be.a('Function');
  });

  it('Should have received "onSpend" function as a prop', () => {
    const mainWrapper = mount(<VoteDisplayer
      cred={dummyCoin}
      sk={{ dummy: 'value' }}
      id={{ dummy: 'value' }}
      ElGamalPK={{ dummy: 'value' }}
      ElGamalSK={{ dummy: 'value' }}
      sk_client={[]}
    />);
    const wrapper = mainWrapper.find(VoteActionButton);
    expect(wrapper.props().onSpend).to.be.a('Function');
  });

  it('Should have received "credState" string as a prop, which is one of attributes of COIN_STATUS', () => {
    const mainWrapper = mount(<VoteDisplayer
      cred={dummyCoin}
      sk={{ dummy: 'value' }}
      id={{ dummy: 'value' }}
      ElGamalPK={{ dummy: 'value' }}
      ElGamalSK={{ dummy: 'value' }}
      sk_client={[]}
    />);
    const wrapper = mainWrapper.find(VoteActionButton);
    const { credState } = wrapper.props();
    expect(credState).to.be.a('string');
    assert.isTrue(credState === COIN_STATUS.created ||
      credState === COIN_STATUS.signing ||
      credState === COIN_STATUS.signed ||
      credState === COIN_STATUS.spent ||
      credState === COIN_STATUS.error);
  });

  it('Should be disabled if "credState" is either "signing", "spending", "spent" or "error"', () => {
    const wrapper1 = shallow(<VoteActionButton
      onSign={() => {
      }}
      onSpend={() => {
      }}
      credState={COIN_STATUS.created}
    />);
    const wrapper2 = shallow(<VoteActionButton
      onSign={() => {
      }}
      onSpend={() => {
      }}
      credState={COIN_STATUS.signing}
    />);
    const wrapper3 = shallow(<VoteActionButton
      onSign={() => {
      }}
      onSpend={() => {
      }}
      credState={COIN_STATUS.signed}
    />);
    const wrapper4 = shallow(<VoteActionButton
      onSign={() => {
      }}
      onSpend={() => {
      }}
      credState={COIN_STATUS.spent}
    />);
    const wrapper5 = shallow(<VoteActionButton
      onSign={() => {
      }}
      onSpend={() => {
      }}
      credState={COIN_STATUS.spending}
    />);
    const wrapper6 = shallow(<VoteActionButton
      onSign={() => {
      }}
      onSpend={() => {
      }}
      credState={COIN_STATUS.error}
    />);

    const buttonNode1 = wrapper1.find(Button);
    const buttonNode2 = wrapper2.find(Button);
    const buttonNode3 = wrapper3.find(Button);
    const buttonNode4 = wrapper4.find(Button);
    const buttonNode5 = wrapper5.find(Button);
    const buttonNode6 = wrapper5.find(Button);

    expect(buttonNode1.props().disabled).to.be.a('boolean').to.equal(false);
    expect(buttonNode2.props().disabled).to.be.a('boolean').to.equal(true);
    expect(buttonNode3.props().disabled).to.be.a('boolean').to.equal(false);
    expect(buttonNode4.props().disabled).to.be.a('boolean').to.equal(true);
    expect(buttonNode5.props().disabled).to.be.a('boolean').to.equal(true);
    expect(buttonNode6.props().disabled).to.be.a('boolean').to.equal(true);
  });
});
