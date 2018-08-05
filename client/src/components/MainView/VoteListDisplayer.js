import React from 'react';
import PropTypes from 'prop-types';
import VoteDisplayer from './VoteDisplayer';

const VoteListDisplayer = props => (
  <div>
    {props.randomizedSignatures.map((randomizedSignature, index) => (
      <VoteDisplayer
        key={index} // if it is not unique, that is client's fault ///////chose something other than x
        randomizedSignature={randomizedSignature}
        coin_params={props.coin_params}
        handleRandomizeDisabled={props.handleRandomizeDisabled}
      />
    ))}
  </div>
);

VoteListDisplayer.propTypes = {
  randomizedSignatures: PropTypes.array.isRequired,
  coin_params: PropTypes.object,
  handleRandomizeDisabled: PropTypes.func.isRequired,
};

export default VoteListDisplayer;
