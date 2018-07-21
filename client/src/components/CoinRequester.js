import React from 'react';
import PropTypes from 'prop-types';
// import ValueInput from './ValueInput';
import SubmitButton from './SubmitButton';
import { params, ctx, COIN_STATUS, signingServers, issuer, DEBUG } from '../config';
import signCoin from '../utils/api';
import CoinSig from '../../lib/CoinSig';
import ElGamal from '../../lib/ElGamal';
import { getSigningCoin } from '../../lib/SigningCoin';
import { publicKeys } from '../cache';

class CoinRequester extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      coinState: COIN_STATUS.uncreated,
      randomizedSignature: null,
      // value: 0,
      isRequesting: false,
    };
  }

  getSignatures = async (serversArg) => {
    const signingCoin =
      getSigningCoin(this.props.coin, this.props.ElGamalPK, this.props.id, this.props.sk, this.props.sk_client);

    const signatures = await Promise.all(serversArg.map(async (server) => {
      try {
        if (DEBUG) {
          console.log(`Sending request to ${server}...`);
        }

        const [h, enc_sig] = await signCoin(server, signingCoin, this.props.ElGamalPK);
        const sig = ElGamal.decrypt(params, this.props.ElGamalSK, enc_sig);

        if (DEBUG) {
          console.log('Decrypted signature:', [h, sig]);
        }

        return [h, sig];
      } catch (err) {
        console.warn(err);
        return null;
      }
    }));
    return signatures;
  };

  aggregateAndRandomizeSignatures = (signatures) => {
    // checks if all authorities signed the coin, if not, return error
    for (let i = 0; i < signatures.length; i++) {
      if (signatures[i] === null) {
        return;
      }
    }
    const aggregateSignature = CoinSig.aggregateSignatures(params, signatures);
    const randomizedSignature = CoinSig.randomize(params, aggregateSignature);
    this.setState({ randomizedSignature });
  };



  // handleInputChange = (value) => {
  //   this.setState({ value });
  // };

  handleSubmit = async (event) => {
    this.setState({ isRequesting: true });
    await this.props.handleCoinSubmit();
    this.setState({ isRequesting: false });

    this.setState({ coinState: COIN_STATUS.created });
  };

  handleCoinSign = async () => {
    this.setState({ coinState: COIN_STATUS.signing });
    if (DEBUG) {
      console.log('Coin sign request(s) were sent');
    }
    const signatures = await this.getSignatures(signingServers);
    this.aggregateAndRandomizeSignatures(signatures);
    if (this.state.randomizedSignature !== null) {
      if (DEBUG) {
        console.log('Coin was signed and signatures were aggregated and randomized.');
      }
      this.setState({ coinState: COIN_STATUS.signed });
    } else {
      if (DEBUG) {
        console.log('There was an error in signing/aggregating the coin');
      }
      this.setState({ coinState: COIN_STATUS.error });
    }
  };

  render() {
    return (
        <SubmitButton
          // isDisabled={this.state.value <= 0 || publicKeys[issuer] == null}
          isLoading={this.state.isRequesting}
          isDisabled={false}
          onSubmit={this.handleSubmit}
          onSign={this.handleCoinSign}
          coinState={this.state.coinState}
        />
    );
  }
}

CoinRequester.propTypes = {
  handleCoinSubmit: PropTypes.func.isRequired,
  coin: PropTypes.shape({
    pk_coin_bytes: PropTypes.arrayOf(PropTypes.number),
    ttl: PropTypes.number,
    // value: PropTypes.number,
    pk_client_bytes: PropTypes.arrayOf(PropTypes.number),
    issuedCoinSig: PropTypes.array,
  }).isRequired,
  sk: PropTypes.shape({
    w: PropTypes.arrayOf(PropTypes.number),
  }).isRequired,
  id: PropTypes.shape({
    w: PropTypes.arrayOf(PropTypes.number),
  }).isRequired,
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
};

export default CoinRequester;
