import React from 'react';
import { Input } from 'semantic-ui-react';
import PropTypes from 'prop-types';

class ValueInput extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      isInputValid: true,
    };
  }

  // only allows integer values
  // server-side check is performed later anyway
  handleInputChange = (event) => {
    const stringValue = event.target.value;
    // ensures that it won't try to extract num from garbage
    // (ex. parseFloat("42.jgp") would have returned 42, if divided by 1, it will return NaN)
    const numValue = parseFloat(stringValue / 1);

    let isInputValid = true;
    if (Number.isInteger(numValue)) { // checks if the value parsed is an integer or a float
      this.props.onInputChange(numValue);
    } else {
      isInputValid = false;
      this.props.onInputChange(0);
    }
    this.setState({ isInputValid });
  };

  render() {
    return (
      <Input
        action={this.props.children}
        actionPosition="left"
        placeholder="Value"
        onChange={this.handleInputChange}
        error={!this.state.isInputValid}
      />
    );
  }
}

ValueInput.propTypes = {
  onInputChange: PropTypes.func.isRequired,
  children: PropTypes.element.isRequired,
};

export default ValueInput;
