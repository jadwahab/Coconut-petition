import React from 'react';
import PropTypes from 'prop-types';
import SubmitButton from './SubmitButton';
import { params, ctx, COIN_STATUS, signingServers, issuer, DEBUG, power } from '../../config';
import { signCoin, getCoin } from '../../utils/api';
import CoinSig from '../../../lib/CoinSig';
import ElGamal from '../../../lib/ElGamal';
import { getSigningCoin } from '../../../lib/SigningCoin';
import { publicKeys } from '../../cache';

class CredentialRequester extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      coin: null,
      sk: null,
      coinState: COIN_STATUS.uncreated,
      randomizedSignature: null,
      isRequesting: false,
    };
  }

  /* eslint-disable */
  generateCoinSecret = () => {
    const [G, o, g1, g2, e, h1] = params;
    const m = ctx.BIG.randomnum(G.order, G.rngGen);
    const pk = ctx.PAIR.G1mul(g1, m);

    // random blindling factor o_blind
    const o_blind = ctx.BIG.randomnum(G.order, G.rngGen);
    const h_blind = ctx.PAIR.G1mul(h1, o_blind);

    pk.add(h_blind);
    pk.affine();

    const sk = {
      m: m,
      o: o_blind
    };

    return [sk, pk];
  };
  /* eslint-enable */

  handleCoinSubmit = async () => {
    const [sk_coin, pk_coin] = this.generateCoinSecret();
    const coin = await getCoin(
      sk_coin,
      pk_coin,
      this.props.pk_client,
      this.props.sk_client,
      issuer,
    );

    if (coin != null) {
      this.setState({ coin });
      this.setState({ sk: sk_coin });
      if (DEBUG) {
        console.log(`Got credential signed by the issuer @${issuer}`);
      }
    }
  };

  getSignatures = async (serversArg) => {
    const signingCoin = getSigningCoin(this.state.coin, this.props.ElGamalSK, this.props.ElGamalPK, this.state.sk, this.props.sk_client);

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

  aggregateSignatures = (signatures) => {
    // checks if all authorities signed the coin, if not, return error
    for (let i = 0; i < signatures.length; i++) {
      if (signatures[i] === null) {
        return;
      }
    }
    return CoinSig.aggregateSignatures(params, signatures);
  }






// BUTTON HANDLER FUNTIONS
  handleSubmit = async (event) => {
    this.setState({ isRequesting: true });
    await this.handleCoinSubmit();
    this.setState({ isRequesting: false });

    this.setState({ coinState: COIN_STATUS.created });
  };

  handleCoinSign = async () => {
    this.setState({ isRequesting: true });
    if (DEBUG) {
      console.log('Coin sign request(s) were sent');
    }
    const signatures = await this.getSignatures(signingServers);

    const aggregatedSignature = this.aggregateSignatures(signatures);
    if (aggregatedSignature === null) {
      if (DEBUG) {
        console.log('There was an error in aggregating the signatures');
      }
      this.setState({ coinState: COIN_STATUS.error });
    }

    this.setState({ randomizedSignature: aggregatedSignature });

    // pass parameters to other component (VoteDisplayer)
    this.props.handleCoinForSpend(this.state.coin, this.state.sk);

    if (this.state.randomizedSignature !== null) {
      if (DEBUG) {
        console.log('Coin was signed by each authority and signatures were aggregated');
      }
      this.setState({ isRequesting: false });
      this.setState({ coinState: COIN_STATUS.signed });
    } else {
      if (DEBUG) {
        console.log('There was an error in signing the coin');
      }
      this.setState({ isRequesting: false });
      this.setState({ coinState: COIN_STATUS.error });
    }
  };

  handleCredentialRandomize = async () => {
    this.setState({ isRequesting: true });
    await this.props.handleRandomize(this.state.randomizedSignature);
    this.setState({ isRequesting: false });
    if (DEBUG) {
      console.log('Signature was randomized');
    }
    this.setState({ coinState: COIN_STATUS.signed });
  }

  render() {
    return (
      <SubmitButton
        isDisabled={this.props.randomizeDisabled}
        isLoading={this.state.isRequesting}
        onSubmit={this.handleSubmit}
        onSign={this.handleCoinSign}
        onRandomize={this.handleCredentialRandomize}
        coinState={this.state.coinState}
      />
    );
  }
}

CredentialRequester.propTypes = {
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
  pk_client: PropTypes.array.isRequired,
  handleRandomize: PropTypes.func.isRequired,
  handleCoinForSpend: PropTypes.func.isRequired,
  randomizeDisabled: PropTypes.bool.isRequired,
};

export default CredentialRequester;
