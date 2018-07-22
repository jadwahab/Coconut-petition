import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';
import { COIN_STATUS, BUTTON_COIN_STATUS } from '../config';

const CoinActionButton = (props) => {
  let buttonContent;
  let handleButtonClick;
  let isDisabled = false;

  switch (props.coinState) {
    case COIN_STATUS.signed: // 'Signed'
      buttonContent = BUTTON_COIN_STATUS.spend; // 'Spend Coin'
      handleButtonClick = props.onSpend;
      break;

    case COIN_STATUS.spent: // 'Spent'
      isDisabled = true;
      buttonContent = BUTTON_COIN_STATUS.spent; // 'Coin was Spent'
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

CoinActionButton.propTypes = {
  onSpend: PropTypes.func.isRequired,
  coinState: PropTypes.string.isRequired,
};

export default CoinActionButton;
