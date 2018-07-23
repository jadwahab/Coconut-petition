import React from 'react';
import PropTypes from 'prop-types';
import { Segment, Button } from 'semantic-ui-react';
import VoteActionButton from './VoteActionButton';
import styles from './VoteDisplayer.style';
import { params, ctx, COIN_STATUS, signingServers, merchant, DEBUG } from '../config';
import { signCoin, spendCoin } from '../utils/api';
import CoinSig from '../../lib/CoinSig';
import ElGamal from '../../lib/ElGamal';
import { getSigningCoin } from '../../lib/SigningCoin';
import { prepareProofOfSecret } from '../../lib/auxiliary';
import { publicKeys } from '../cache';

class VoteDisplayer extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      coinState: COIN_STATUS.signed,
      remainingValidityString: '',
    };
  }

  componentDidMount() {
    // this.timer = setInterval(this.updateRemainingValidityString, 200);
  }

  componentWillUnmount() {
    clearInterval(this.timer);
  }



  updateRemainingValidityString = () => {
    let remainingValidityString;
    switch (this.state.coinState) {
      case COIN_STATUS.spent: {
        remainingValidityString = 'Coin was spent';
        clearInterval(this.timer);
        break;
      }
      case COIN_STATUS.error: {
        remainingValidityString = 'Error occurred';
        clearInterval(this.timer);
        break;
      }
      default: {
        const currentTime = new Date().getTime();
        const td = this.props.coin.ttl - currentTime;
        const seconds = Math.floor((td / 1000) % 60);
        const minutes = Math.floor((td / 1000 / 60) % 60);
        const hours = Math.floor((td / (1000 * 60 * 60)));

        const ss = (`0${seconds}`).slice(-2);
        const mm = (`0${minutes}`).slice(-2);
        const hh = (`0${hours}`).slice(-2);
        remainingValidityString = `${hh}:${mm}:${ss}`;
        break;
      }
    }

    this.setState({ remainingValidityString: remainingValidityString });
  };

  aggregate_pkX_component = (signingAuthoritiesPublicKeys) => {
    const aX3 = new ctx.ECP2();
    Object.entries(signingAuthoritiesPublicKeys).forEach(([server, publicKey]) => {
      aX3.add(publicKey[4]); // publicKey has structure [g, X0, X1, X2, X3, X4], so we access element at 4th index
    });
    aX3.affine();

    return aX3;
  };


  handleCoinSpend = async () => {

    console.log(this.props.randomizedSignature);

    this.setState({ coinState: COIN_STATUS.spending });

    const signingAuthoritiesPublicKeys = Object.keys(publicKeys)
      .filter(server => signingServers.includes(server))
      .reduce((obj, server) => {
        obj[server] = publicKeys[server];
        return obj;
      }, {});

    const aX3 = this.aggregate_pkX_component(signingAuthoritiesPublicKeys);
    const pkX = ctx.PAIR.G2mul(aX3, this.props.coin_params.sk);


    const merchantStr = publicKeys[merchant].join('');
    const secretProof = prepareProofOfSecret(params, this.props.coin_params.sk, merchantStr, aX3);

    if (DEBUG) {
      console.log('Coin spend request was sent');
    }

    const success = await spendCoin(this.props.coin_params.coin, secretProof, this.props.randomizedSignature, pkX, this.props.coin_params.id, merchant);
    if (success) {
      if (DEBUG) {
        console.log('Coin was successfully spent.');
      }
      this.setState({ coinState: COIN_STATUS.spent });
    } else {
      if (DEBUG) {
        console.log('There was an error in spending the coin');
      }
      this.setState({ coinState: COIN_STATUS.error });
    }
  };

  render() {
    return (
      <Segment.Group horizontal>
        {/*<Segment style={styles.segmentStyle}><b>Valid for:</b> {this.state.remainingValidityString}</Segment>*/}
        {/*add time left for petition later*/}

        <Segment style={styles.segmentStyle}>
          <VoteActionButton
            onSpend={this.handleCoinSpend}
            coinState={this.state.coinState}
          />
        </Segment>
      </Segment.Group>
    );
  }
}

VoteDisplayer.propTypes = {
  randomizedSignature: PropTypes.array.isRequired,
  coin_params: PropTypes.object,
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
};

export default VoteDisplayer;
