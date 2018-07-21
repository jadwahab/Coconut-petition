import React from 'react';
import PropTypes from 'prop-types';
// import ValueInput from './ValueInput';
import SubmitButton from './SubmitButton';
import { params, ctx, COIN_STATUS, signingServers, issuer, DEBUG } from '../config';
import { signCoin, getCoin } from '../utils/api';
import CoinSig from '../../lib/CoinSig';
import ElGamal from '../../lib/ElGamal';
import { getSigningCoin } from '../../lib/SigningCoin';
import { publicKeys } from '../cache';

class CoinRequester extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      coin: null,
      sk: null,
      id: null,
      coinState: COIN_STATUS.uncreated,
      randomizedSignature: null,
      // value: 0,
      isRequesting: false,
    };
  }


  generateCoinSecret = () => {
    const [G, o, g1, g2, e] = params;
    const sk = ctx.BIG.randomnum(G.order, G.rngGen);
    const pk = ctx.PAIR.G2mul(g2, sk);
    return [sk, pk];
  };

  handleCoinSubmit = async () => {
    const [sk_coin, pk_coin] = this.generateCoinSecret();
    const [coin, id] = await getCoin(
      sk_coin,
      pk_coin,
      // value,
      this.props.pk_client,
      this.props.sk_client,
      issuer,
    );

    if (coin != null && id != null) {
      this.setState({ coin });
      this.setState({ sk: sk_coin });
      this.setState({ id });
    };
  };

  getSignatures = async (serversArg) => {
    const signingCoin =
      getSigningCoin(this.state.coin, this.props.ElGamalPK, this.state.id, this.state.sk, this.props.sk_client);

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
    await this.handleCoinSubmit();
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
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
  pk_client: PropTypes.array.isRequired,
};

export default CoinRequester;
