import React from 'react';
import PropTypes from 'prop-types';
import { Segment } from 'semantic-ui-react';
import VoteActionButton from './VoteActionButton';
import InputPetitionID from './InputPetitionID';
import styles from './VoteDisplayer.style';
import { params, CRED_STATUS, signingServers, petitionOwner, DEBUG } from '../../config';
import { spendCred } from '../../utils/api';
import CredSig from '../../../lib/CredSig';
import { make_proof_credentials_petition, verify_proof_credentials_petition } from '../../../lib/Proofs';
import { publicKeys } from '../../cache';

class VoteDisplayer extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      credState: CRED_STATUS.signed,
      petitionID: null,
      // remainingValidityString: '',
    };
  }

  // componentDidMount() {
  //   this.timer = setInterval(this.updateRemainingValidityString, 200);
  // }

  // componentWillUnmount() {
  //   clearInterval(this.timer);
  // }

  // updateRemainingValidityString = () => {
  //   let remainingValidityString;
  //   switch (this.state.credState) {
  //     case CRED_STATUS.spent: {
  //       remainingValidityString = 'Cred was spent';
  //       clearInterval(this.timer);
  //       break;
  //     }
  //     case CRED_STATUS.error: {
  //       remainingValidityString = 'Error occurred';
  //       clearInterval(this.timer);
  //       break;
  //     }
  //     default: {
  //       const currentTime = new Date().getTime();
  //       const td = this.props.cred.ttl - currentTime;
  //       const seconds = Math.floor((td / 1000) % 60);
  //       const minutes = Math.floor((td / 1000 / 60) % 60);
  //       const hours = Math.floor((td / (1000 * 60 * 60)));

  //       const ss = (`0${seconds}`).slice(-2);
  //       const mm = (`0${minutes}`).slice(-2);
  //       const hh = (`0${hours}`).slice(-2);
  //       remainingValidityString = `${hh}:${mm}:${ss}`;
  //       break;
  //     }
  //   }

  //   this.setState({ remainingValidityString: remainingValidityString });
  // };

  handleCredSpend = async () => {
    this.setState({ credState: CRED_STATUS.spending });

    const signingAuthoritiesPublicKeys = Object.keys(publicKeys)
      .filter(server => signingServers.includes(server))
      .reduce((obj, server) => {
        obj[server] = publicKeys[server];
        return obj;
      }, {});

    const aggregatePublicKey = CredSig.aggregatePublicKeys_obj(params, signingAuthoritiesPublicKeys);

    const petitionOwnerStr = publicKeys[petitionOwner].join('');

    const MPCP_output = make_proof_credentials_petition(params, aggregatePublicKey,
      this.props.randomizedSignature, this.props.cred_params.sk.m, petitionOwnerStr, this.state.petitionID);

    const success = await spendCred(MPCP_output, this.props.randomizedSignature, petitionOwner, this.state.petitionID);
    if (success) {
      if (DEBUG) {
        console.log('Signature verified');
      }
      this.setState({ credState: CRED_STATUS.spent }); // EDIT:
      this.props.handleRandomizeDisabled(false);
    } else {
      if (DEBUG) {
        console.log('There was an error in verifying signature');
      }
      this.setState({ credState: CRED_STATUS.error });// EDIT:
    }

  };

  handleInputChange = (petitionID) => {
    this.setState({ petitionID: petitionID.toString() });
  };

  render() {
    return (
      <Segment.Group horizontal>
        <Segment style={styles.segmentStyle}>
          <InputPetitionID onInputChange={this.handleInputChange}>
            <VoteActionButton
              onSpend={this.handleCredSpend}
              credState={this.state.credState}
              voteDisabled={this.state.petitionID == null}
            />
          </InputPetitionID>
        </Segment>

        {/*<Segment style={styles.segmentStyle}><b>Valid for:</b> {this.state.remainingValidityString}</Segment>*/}
        {/*EDIT: add time left for petition later*/}
      </Segment.Group>
    );
  }
}

VoteDisplayer.propTypes = {
  randomizedSignature: PropTypes.array.isRequired,
  cred_params: PropTypes.object,
  handleRandomizeDisabled: PropTypes.func.isRequired,
};

export default VoteDisplayer;
