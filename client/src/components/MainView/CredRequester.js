import React from 'react';
import PropTypes from 'prop-types';
import SubmitButton from './SubmitButton';
import { params, ctx, CRED_STATUS, signingServers, issuer, DEBUG } from '../../config';
import { signCred, getCred } from '../../utils/api';
import CredSig from '../../../lib/CredSig';
import ElGamal from '../../../lib/ElGamal';
import { getSigningCred } from '../../../lib/SigningCred';
import { publicKeys } from '../../cache';

class CredRequester extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      cred: null,
      sk: null,
      credState: CRED_STATUS.created,
      randomizedSignature: null,
      isRequesting: false,
    };
  }

  /* eslint-disable */
  generateCredSecret = () => {
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

  handleCredSubmit = async () => {
    const [sk_cred, pk_cred] = this.generateCredSecret();
    const cred = await getCred(
      sk_cred,
      pk_cred,
      this.props.pk_client,
      this.props.sk_client,
      issuer,
    );

    if (cred != null) {
      this.setState({ cred });
      this.setState({ sk: sk_cred });
      if (DEBUG) {
        console.log(`Got credential signed by the issuer @${issuer}`);
      }
    }
  };

  getSignatures = async (serversArg) => {
    const [G, o, g1, g2, e, h1] = params;
    
    const [sk_cred, pk_cred] = this.generateCredSecret();

    //
    const pk_cred_bytes = [];
    pk_cred.toBytes(pk_cred_bytes);
    const reducer = (acc, cur) => acc + cur;
    const requestStr =
      this.props.pk_client.reduce(reducer) + // client's key
      pk_cred_bytes.reduce(reducer); // cred's pk

    const sha = ctx.ECDH.HASH_TYPE;

    const C = [];
    const D = [];

    // to 'authorise' the request
    ctx.ECDH.ECPSP_DSA(sha, G.rngGen, this.props.sk_client, requestStr, C, D);
    const requestSig = [C, D];

    const cred = {
      pk_cred_bytes: pk_cred_bytes,
      pk_client_bytes: this.props.pk_client,
      // requestSig: requestSig,
    };

    this.setState({ cred: cred });
    this.setState({ sk: sk_cred });
    //

    const signingCred = getSigningCred(cred, this.props.ElGamalSK, 
      this.props.ElGamalPK, sk_cred, this.props.sk_client);

    const signatures = await Promise.all(serversArg.map(async (server) => {
      try {
        if (DEBUG) {
          console.log(`Sending request to ${server}...`);
        }

        const [h, enc_sig] = await signCred(server, signingCred, this.props.ElGamalPK);
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
    // checks if all authorities signed the cred, if not, return error
    for (let i = 0; i < signatures.length; i++) {
      if (signatures[i] === null) {
        return;
      }
    }
    return CredSig.aggregateSignatures(params, signatures);
  }






// BUTTON HANDLER FUNTIONS

// handleSubmit = async (event) => {
  //   this.setState({ isRequesting: true });
  //   await this.handleCredSubmit();
  //   this.setState({ isRequesting: false });

  //   this.setState({ credState: CRED_STATUS.created });
  // };

  handleCredSign = async () => {
    this.setState({ isRequesting: true });
    if (DEBUG) {
      console.log('Cred sign request(s) were sent');
    }
    const signatures = await this.getSignatures(signingServers);

    const aggregatedSignature = this.aggregateSignatures(signatures);
    if (aggregatedSignature === null) {
      if (DEBUG) {
        console.log('There was an error in aggregating the signatures');
      }
      this.setState({ credState: CRED_STATUS.error });
    }

    this.setState({ randomizedSignature: aggregatedSignature });

    // pass parameters to other component (VoteDisplayer)
    this.props.handleCredForSpend(this.state.cred, this.state.sk);

    if (this.state.randomizedSignature !== null) {
      if (DEBUG) {
        console.log('Cred was signed by each authority and signatures were aggregated');
      }
      this.setState({ isRequesting: false });
      this.setState({ credState: CRED_STATUS.signed });
    } else {
      if (DEBUG) {
        console.log('There was an error in signing the cred');
      }
      this.setState({ isRequesting: false });
      this.setState({ credState: CRED_STATUS.error });
    }
  };

  handleCredentialRandomize = async () => {
    this.setState({ isRequesting: true });
    await this.props.handleRandomize(this.state.randomizedSignature);
    this.setState({ isRequesting: false });
    if (DEBUG) {
      console.log('Signature was randomized');
    }
    this.setState({ credState: CRED_STATUS.signed });
  }

  render() {
    return (
      <SubmitButton
        isDisabled={this.props.randomizeDisabled}
        isLoading={this.state.isRequesting}
        // onSubmit={this.handleSubmit}
        onSign={this.handleCredSign}
        onRandomize={this.handleCredentialRandomize}
        credState={this.state.credState}
      />
    );
  }
}

CredRequester.propTypes = {
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
  pk_client: PropTypes.array.isRequired,
  handleRandomize: PropTypes.func.isRequired,
  handleCredForSpend: PropTypes.func.isRequired,
  randomizeDisabled: PropTypes.bool.isRequired,
};

export default CredRequester;
