import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';

const ResetCacheButton = props => (
  <Button
    primary={true}
    content="Reset PK Cache"
    onClick={props.onClickCallback}
  />
);

ResetCacheButton.propTypes = {
  onClickCallback: PropTypes.func.isRequired,
};

export default ResetCacheButton;
