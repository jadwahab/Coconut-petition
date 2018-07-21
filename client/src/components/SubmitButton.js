import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';
import { COIN_STATUS, BUTTON_COIN_STATUS } from '../config';

const SubmitButton = (props) => {
  let buttonContent;
  let handleButtonClick;
  let isDisabled = false;

  switch (props.coinState) {
    case COIN_STATUS.uncreated: // 'Ungenerated'
      buttonContent = BUTTON_COIN_STATUS.get; // 'Get Credential'
      handleButtonClick = props.onSubmit;
      break;

    case COIN_STATUS.created: // 'Generated'
      buttonContent = BUTTON_COIN_STATUS.sign; // 'Sign Coin'
      handleButtonClick = props.onSign;
      break;

    case COIN_STATUS.signing: // 'Signing'
      isDisabled = true;
      buttonContent = BUTTON_COIN_STATUS.signing; // 'Signing...'
      break;

    case COIN_STATUS.signed: // 'Signed'
      isDisabled = true;
      buttonContent = BUTTON_COIN_STATUS.spend; // 'Spend Coin'
      break;

    default:
      break;
  }



  return (
    <Button
      disabled={props.isDisabled}
      color="teal"
      labelPosition="left"
      icon="key"
      content={buttonContent}
      onClick={handleButtonClick}
      loading={props.isLoading}
    />
  );
};

SubmitButton.propTypes = {
  isDisabled: PropTypes.bool.isRequired,
  isLoading: PropTypes.bool.isRequired,
  onSubmit: PropTypes.func.isRequired,
  onSign: PropTypes.func.isRequired,
  coinState: PropTypes.string.isRequired,
};

export default SubmitButton;
