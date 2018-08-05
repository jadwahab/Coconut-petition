import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';
import { COIN_STATUS, BUTTON_COIN_STATUS } from '../../config';

const SubmitButton = (props) => {
  let buttonContent;
  let handleButtonClick;
  let isDisabled = false;
  let buttonIcon = "key"

  switch (props.coinState) {
    case COIN_STATUS.uncreated: // 'Ungenerated'
      buttonContent = BUTTON_COIN_STATUS.get; // 'Get Credential'
      handleButtonClick = props.onSubmit;
      break;

    case COIN_STATUS.created: // 'Generated'
      buttonContent = BUTTON_COIN_STATUS.sign; // 'Sign Credential'
      handleButtonClick = props.onSign;
      break;

    case COIN_STATUS.signed: // 'Signed'
      buttonContent = BUTTON_COIN_STATUS.ready; // 'Credential Ready'
      handleButtonClick = props.onRandomize;
      buttonIcon = 'check';
      break;
    
    case COIN_STATUS.error:
      isDisabled = true;
      buttonContent = BUTTON_COIN_STATUS.error; //  'Error'
      buttonIcon = 'warning';
      break;

    default:
      break;
  }



  return (
    <Button
      disabled={props.isDisabled}
      color="teal"
      labelPosition="left"
      icon={buttonIcon}
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
  onRandomize: PropTypes.func.isRequired,
  coinState: PropTypes.string.isRequired,
};

export default SubmitButton;
