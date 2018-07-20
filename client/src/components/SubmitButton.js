import React from 'react';
import { Button } from 'semantic-ui-react';
import PropTypes from 'prop-types';

const SubmitButton = props => (
  <Button
    disabled={props.isDisabled}
    color="teal"
    labelPosition="left"
    icon="key"
    content="Get Credential"
    onClick={props.onSubmit}
    loading={props.isLoading}
  />
);

SubmitButton.propTypes = {
  isDisabled: PropTypes.bool.isRequired,
  isLoading: PropTypes.bool.isRequired,
  onSubmit: PropTypes.func.isRequired,
};

export default SubmitButton;
