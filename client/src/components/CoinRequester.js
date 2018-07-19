import React from 'react';
import PropTypes from 'prop-types';
import ValueInput from './ValueInput';
import SubmitButton from './SubmitButton';
import { publicKeys } from '../cache';
import { issuer } from '../config';

class CoinRequester extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      value: 0,
      isRequesting: false,
    };
  }

  handleInputChange = (value) => {
    this.setState({ value });
  };

  handleSubmit = async (event) => {
    this.setState({ isRequesting: true });
    await this.props.handleCoinSubmit(this.state.value);
    this.setState({ isRequesting: false });
  };

  render() {
    return (
      <ValueInput onInputChange={this.handleInputChange}>
        <SubmitButton
          onSubmit={this.handleSubmit}
          isLoading={this.state.isRequesting}
          isDisabled={this.state.value <= 0 || publicKeys[issuer] == null}
        />
      </ValueInput>
    );
  }
}

CoinRequester.propTypes = {
  handleCoinSubmit: PropTypes.func.isRequired,
};

export default CoinRequester;
