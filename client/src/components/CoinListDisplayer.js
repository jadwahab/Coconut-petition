import React from 'react';
import PropTypes from 'prop-types';
import CoinDisplayer from './CoinDisplayer';

const CoinListDisplayer = props => (
  <div>
    {props.randomizedSignatures.map( (randomizedSignature, index) => (
      <CoinDisplayer
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

CoinListDisplayer.propTypes = {
  randomizedSignatures: PropTypes.array.isRequired,
  coin_params: PropTypes.object,
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
};

export default CoinListDisplayer;
