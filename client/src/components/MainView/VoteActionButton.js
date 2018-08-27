import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';
import { CRED_STATUS, BUTTON_CRED_STATUS } from '../../config';

const VoteActionButton = (props) => {
  let buttonContent;
  let handleButtonClick;
  let isDisabled = props.voteDisabled;

  switch (props.credState) {
    case CRED_STATUS.signed: // 'Signed'
      buttonContent = BUTTON_CRED_STATUS.spend; // 'Spend Cred'
      handleButtonClick = props.onSpend;
      break;

    case CRED_STATUS.spent: // 'Spent'
      isDisabled = true;
      buttonContent = BUTTON_CRED_STATUS.spent; // 'Cred was Spent'
      break;

    case CRED_STATUS.spending: // 'Spending'
      isDisabled = true;
      buttonContent = BUTTON_CRED_STATUS.spending; // 'Spending...'
      break;

    case CRED_STATUS.error: // 'Error'
      isDisabled = true;
      buttonContent = BUTTON_CRED_STATUS.error; // 'Error'
      break;

    default:
      break;
  }

  return (
    <div>
      <Button
        disabled={isDisabled}
        primary={true}
        content={buttonContent}
        onClick={handleButtonClick}
      />
      <Button
        disabled={isDisabled}
        primary={true}
        content={buttonContent}
        onClick={handleButtonClick}
      />
    </div>
  );
};

VoteActionButton.propTypes = {
  onSpend: PropTypes.func.isRequired,
  credState: PropTypes.string.isRequired,
  voteDisabled: PropTypes.bool.isRequired,
};

export default VoteActionButton;
