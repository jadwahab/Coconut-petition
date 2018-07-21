import React from 'react';
import PropTypes from 'prop-types';
import CoinDisplayer from './CoinDisplayer';

const CoinListDisplayer = props => (
  <div>
    {props.randomizedSignatures.map(randomizedSignature => (
      <CoinDisplayer
        key={randomizedSignature.x.toString()} // if it is not unique, that is client's fault ///////chose something other than x
        randomizedSignature={randomizedSignature}
        ElGamalSK={props.ElGamalSK}
        ElGamalPK={props.ElGamalPK}
        sk_client={props.sk_client}
      />
    ))}
  </div>
);

CoinListDisplayer.propTypes = {
  randomizedSignatures: PropTypes.array.isRequired,
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
};

export default CoinListDisplayer;
