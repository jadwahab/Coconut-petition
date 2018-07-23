import React from 'react';
import PropTypes from 'prop-types';
import VoteDisplayer from './VoteDisplayer';

const VoteListDisplayer = props => (
  <div>
    {props.randomizedSignatures.map( (randomizedSignature, index) => (
      <VoteDisplayer
        key={index} // if it is not unique, that is client's fault ///////chose something other than x
        randomizedSignature={randomizedSignature}
        coin_params={props.coin_params}
        ElGamalSK={props.ElGamalSK}
        ElGamalPK={props.ElGamalPK}
        sk_client={props.sk_client}
      />
    ))}
  </div>
);

VoteListDisplayer.propTypes = {
  randomizedSignatures: PropTypes.array.isRequired,
  coin_params: PropTypes.object,
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
};

export default VoteListDisplayer;
