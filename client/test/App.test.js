import React from 'react';
import { Header } from 'semantic-ui-react';
import { expect } from 'chai';
import { shallow, mount, render } from 'enzyme';
import App from '../src/components/App';
import MainView from '../src/components/MainView';
import TopMenu from '../src/components/TopMenu';
import ServerStatuses from '../src/components/ServerStatuses';
import Footer from '../src/components/Footer';

describe('App Component', () => {
  it('Should have three children', () => {
    const wrapper = shallow(<App />);
    expect(wrapper.children().length).to.equal(3);
  });

  it('Contains a TopMenu component', () => {
    const wrapper = mount(<App />);
    expect(wrapper.find(TopMenu)).to.have.length(1);
  });

  it('Contains a Footer component', () => {
    const wrapper = mount(<App />);
    expect(wrapper.find(Footer)).to.have.length(1);
  });

  it('Contains a div with MainView and ServerStatuses components', () => {
    const wrapper = mount(<App />);
    expect(wrapper.find('div').find(MainView)).to.have.length(1);
    expect(wrapper.find('div').find(ServerStatuses)).to.have.length(1);
  });
});
