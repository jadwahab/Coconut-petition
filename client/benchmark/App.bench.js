import React from 'react';
import { expect } from 'chai';
import { shallow, mount, render } from 'enzyme';
import App from '../src/components/App';
import CoinRequester from '../src/components/CoinRequester';
import CoinDisplayer from '../src/components/CoinDisplayer';

const MAX_REPETITIONS = 10;
const NUMBER_OF_CLIENTS = 1;

const getCoin = async (wrapper, i) => {
  const t0 = performance.now();
  await wrapper.find(CoinRequester).at(0).props().handleCoinSubmit(1);
  const t1 = performance.now();
  console.log(`Clientside coin request ${i} - took ${t1 - t0}`);
};

const signCoin = async (wrapper, coinnum, i) => {
  const t0 = performance.now();
  await wrapper.find(CoinDisplayer).at(coinnum).instance().handleCoinSign();
  const t1 = performance.now();
  console.log(`Clientside coin sign ${i} - took ${t1 - t0}`);
};

const spendCoin = async (wrapper, coinnum, i) => {
  const t0 = performance.now();
  await wrapper.find(CoinDisplayer).at(coinnum).instance().handleCoinSpend();
  const t1 = performance.now();
  console.log(`Clientside coin spend ${i} - took ${t1 - t0}`);
};

// use below to benchmark authorites but change config.js to introduce more authorities (and other servers)

describe('Benchmarking Clients', () => {
  it('Coin Issuance, Sign, Spend', async () => {
    const wrapper = mount(<App />);
    for (let i = 0; i < MAX_REPETITIONS + 2; i++) {
      const t0 = performance.now();
      await Promise.all([
        getCoin(wrapper, 1),
        // getCoin(wrapper, 2),
      ]);
      const t1 = performance.now();
      wrapper.update();
      const t2 = performance.now();
      await Promise.all([
        signCoin(wrapper, NUMBER_OF_CLIENTS * i, 1),
        // signCoin(wrapper, ((NUMBER_OF_CLIENTS * i) + 1), 2),
      ]);
      const t3 = performance.now();
      await Promise.all([
        spendCoin(wrapper, NUMBER_OF_CLIENTS * i, 1),
        // spendCoin(wrapper, ((NUMBER_OF_CLIENTS * i) + 1), 2),
      ]);
      const t4 = performance.now();
      if (i >= 2) {
        console.log(`Issue:${t1 - t0},Sign:${t3 - t2},Spend:${t4 - t3}`);
      }
    }
  });
});
