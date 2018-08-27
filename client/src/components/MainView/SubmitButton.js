import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';
import { CRED_STATUS, BUTTON_CRED_STATUS } from '../../config';

const SubmitButton = (props) => {
  let buttonContent;
  let handleButtonClick;
  let isDisabled = false; // EDIT:
  let buttonIcon = 'key';

  switch (props.credState) {
    // case CRED_STATUS.uncreated: // 'Ungenerated'
    //   buttonContent = BUTTON_CRED_STATUS.get; // 'Get Credential'
    //   handleButtonClick = props.onSubmit;
    //   break;

    case CRED_STATUS.created: // 'Generated'
      buttonContent = BUTTON_CRED_STATUS.sign; // 'Sign Credential'
      handleButtonClick = props.onSign;
      break;

    case CRED_STATUS.signed: // 'Signed'
      buttonContent = BUTTON_CRED_STATUS.ready; // 'Credential Ready'
      handleButtonClick = props.onRandomize;
      buttonIcon = 'retweet';
      break;
    
    case CRED_STATUS.error:
      isDisabled = true;
      buttonContent = BUTTON_CRED_STATUS.error; //  'Error'
      buttonIcon = 'warning';
      break;

    default:
      break;
  }

  return (
    <Button
      disabled={props.isDisabled || isDisabled}
      color="instagram"
      labelPosition="right"
      icon={buttonIcon}
      content={buttonContent}
      onClick={handleButtonClick}
      loading={props.isLoading}
      size='huge'
    />
  );
};

SubmitButton.propTypes = {
  isDisabled: PropTypes.bool.isRequired,
  isLoading: PropTypes.bool.isRequired,
  // onSubmit: PropTypes.func.isRequired,
  onSign: PropTypes.func.isRequired,
  onRandomize: PropTypes.func.isRequired,
  credState: PropTypes.string.isRequired,
};

export default SubmitButton;
