import React from 'react';
import PropTypes from 'prop-types';
import SubmitButton from './SubmitButton';
import { params, ctx, COIN_STATUS, signingServers, issuer, DEBUG } from '../../config';
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
      id: null,
      coinState: COIN_STATUS.uncreated,
      randomizedSignature: null,
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

  // aggregateAndRandomizeSignatures = (signatures) => {          // DELETE LATER
  //   // checks if all authorities signed the coin, if not, return error
  //   for (let i = 0; i < signatures.length; i++) {
  //     if (signatures[i] === null) {
  //       return;
  //     }
  //   }
  //   const aggregateSignature = CoinSig.aggregateSignatures(params, signatures);
  //   const randomizedSignature = CoinSig.randomize(params, aggregateSignature);
  //   this.setState({ randomizedSignature });
  // };

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

    // this.aggregateAndRandomizeSignatures(signatures); DELETE LATER

    const aggregatedSignature = this.aggregateSignatures(signatures);
    // const randomizedSignature = CoinSig.randomize(params, aggregatedSignature);

    let randomizedSignature = this.props.handleRandomize(aggregatedSignature);

    this.setState({ randomizedSignature });

    // pass parameters to other component (VoteDisplayer)
    this.props.handleCoinForSpend(this.state.coin, this.state.sk, this.state.id);

    if (this.state.randomizedSignature !== null) {
      if (DEBUG) {
        console.log('Coin was signed and signatures were aggregated and randomized.');
      }
      this.setState({ isRequesting: false });
      this.setState({ coinState: COIN_STATUS.signed });
    } else {
      if (DEBUG) {
        console.log('There was an error in signing/aggregating the coin');
      }
      this.setState({ coinState: COIN_STATUS.error });
    }
  };

  handleCredentialRandomize = async () => {
    this.setState({ isRequesting: true });
    let secondrand = await this.props.handleRandomize(this.state.randomizedSignature);
    this.setState({ isRequesting: false });

    this.setState({ coinState: COIN_STATUS.signed });

//////////////////
    console.log('handleCredentialRandomize');
    console.log(secondrand);
  }

  render() {
    return (
        <SubmitButton
          // isDisabled={this.state.randomizedSignature!=null}
          isDisabled={false}
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
};

export default CredentialRequester;
