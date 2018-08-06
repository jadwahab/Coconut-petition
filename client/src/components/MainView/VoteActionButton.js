import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';
import { COIN_STATUS, BUTTON_COIN_STATUS } from '../../config';

const VoteActionButton = (props) => {
  let buttonContent;
  let handleButtonClick;
  let isDisabled = props.voteDisabled;

  switch (props.credState) {
    case COIN_STATUS.signed: // 'Signed'
      buttonContent = BUTTON_COIN_STATUS.spend; // 'Spend Cred'
      handleButtonClick = props.onSpend;
      break;

    case COIN_STATUS.spent: // 'Spent'
      isDisabled = true;
      buttonContent = BUTTON_COIN_STATUS.spent; // 'Cred was Spent'
      break;

    case COIN_STATUS.spending: // 'Spending'
      isDisabled = true;
      buttonContent = BUTTON_COIN_STATUS.spending; // 'Spending...'
      break;

    case COIN_STATUS.error: // 'Error'
      isDisabled = true;
      buttonContent = BUTTON_COIN_STATUS.error; // 'Error'
      break;

    default:
      break;
  }

  return (
    <Button
      disabled={isDisabled}
      primary={true}
      content={buttonContent}
      onClick={handleButtonClick}
    />
  );
};

VoteActionButton.propTypes = {
  onSpend: PropTypes.func.isRequired,
  credState: PropTypes.string.isRequired,
  voteDisabled: PropTypes.bool.isRequired,
};

export default VoteActionButton;
