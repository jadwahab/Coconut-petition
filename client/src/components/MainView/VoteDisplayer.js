import React from 'react';
import PropTypes from 'prop-types';
import { Segment, Button } from 'semantic-ui-react';
import InputPetitionID from './InputPetitionID';
import styles from './VoteDisplayer.style';
import { ctx, params, CRED_STATUS, signingServers, petitionOwner, DEBUG } from '../../config';
import { voteCred } from '../../utils/api';
import CredSig from '../../../lib/CredSig';
import { make_proof_credentials_petition, make_proof_vote_petition } from '../../../lib/Proofs';
import { publicKeys } from '../../cache';

class VoteDisplayer extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      credState: CRED_STATUS.signed, // EDIT: remove unused
      petitionID: null,
      hasVoted: false,
      voteResult: null,
      currentVoteIcon: null,
      resultButtonColor: 'grey',
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

  getSigningAuthorityElGamal = async (server) => {
    let pkElGamal;
    try {
      let response = await fetch(`http://${server}/pk`);
      response = await response.json();
      const pkElGamalBytes = response.pkElGamal;
      pkElGamal = ctx.ECP.fromBytes(pkElGamalBytes);
    } catch (err) {
      console.log(err);
      console.warn(`Call to ${server} was unsuccessful`);
    }
    return pkElGamal;
  }

  handleInputChange = (petitionID) => {
    this.setState({ petitionID: petitionID.toString() });
  };

  handleVoteYes = () => {
    this.setState({ currentVoteIcon: 'thumbs up' });
    this.handleCredVote(1);
  };

  handleVoteNo = () => {
    this.setState({ currentVoteIcon: 'thumbs down' });
    this.handleCredVote(0);
  };

  handleVoteResult = async () => {
    try {
      const response = await fetch(`http://${petitionOwner}/result/${this.state.petitionID}`);
      if (response.status === 200) {
        const responseJSON = await response.json();
        const petitionResult = responseJSON.petitionResult;
        const yesVotes = parseInt(petitionResult.result.yes, 16);
        const noVotes = parseInt(petitionResult.result.no, 16);

        // if petition passed thumbs up, else thumbs down
        if (yesVotes > noVotes) {
          this.setState({ currentVoteIcon: 'check' });
          this.setState({ resultButtonColor: 'green' });
        } else if (yesVotes === noVotes) {
          this.setState({ currentVoteIcon: 'minus' });
        } else {
          this.setState({ currentVoteIcon: 'x' });
          this.setState({ resultButtonColor: 'red' });
        }
        this.setState({ voteResult: `Petition ${petitionResult.petitionID}:    ${yesVotes}-${noVotes}` });
      } else {
        this.setState({ currentVoteIcon: 'exclamation circle' });
        this.setState({ voteResult: `Petition ${this.state.petitionID} has not ended` });
      }
    } catch (err) {
      console.log(err);
      console.warn(`Call to ${petitionOwner} was unsuccessful`);
    }
  };

  handleCredVote = async (vote) => {
    this.setState({ credState: CRED_STATUS.spending });

    // MPCP:
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

    // MPVP:
    const signingAuthoritiesElGamal = [];
    await Promise.all(signingServers.map(async (server) => {
      try {
        const publicKey = await this.getSigningAuthorityElGamal(server);
        signingAuthoritiesElGamal.push(publicKey);
      } catch (err) {
        console.warn(err);
      }
    }));
    const aggregateElGamal = CredSig.aggregateElGamalPublicKeys(params, signingAuthoritiesElGamal);

    let enc_votes;
    let MPVP_output;
    if (vote === 1) {
      [enc_votes, MPVP_output] = make_proof_vote_petition(params, aggregateElGamal, 1);
    } else {
      [enc_votes, MPVP_output] = make_proof_vote_petition(params, aggregateElGamal, 0);
    }

    const [success, error_msg] = await voteCred(MPCP_output, this.props.randomizedSignature, 
      petitionOwner, this.state.petitionID, enc_votes, MPVP_output);

    if (success) {
      if (DEBUG) {
        console.log('Signature verified');
      }
      this.setState({ credState: CRED_STATUS.spent }); // EDIT: delete but check

      this.props.handleRandomizeDisabled(false);
      this.setState({ voteResult: `Voted for petition: ${this.state.petitionID}!` });
    } else {
      switch (error_msg) {
        case 'sig':
          if (DEBUG) {
            console.log('There was an error in verifying signature');
          }
          this.setState({ currentVoteIcon: 'exclamation circle' });
          this.setState({ voteResult: 'Error in voting!' });
          break;   
        case 'used':
          if (DEBUG) {
            console.log('Already voted for this petition');
          }
          this.setState({ currentVoteIcon: 'exclamation circle' });
          this.setState({ voteResult: `Already voted for petition ${this.state.petitionID}!` });
          break;
        case 'ended':
          if (DEBUG) {
            console.log('This petition has ended');
          }
          this.setState({ currentVoteIcon: 'exclamation circle' });
          this.setState({ voteResult: `Petition ${this.state.petitionID} ended!` });
          break;
        default:
          if (DEBUG) {
            console.log('Unknown error');
          }
          this.setState({ currentVoteIcon: 'exclamation circle' });
          this.setState({ voteResult: 'Error in voting!' });
          break;
      }
      this.setState({ credState: CRED_STATUS.error });// EDIT: delete but check

      this.props.handleRandomizeDisabled(false);
    }
    this.setState({ hasVoted: true });
  };

  render() {
    return (
      <Segment.Group horizontal>
        <Segment style={styles.segmentStyle} size='huge'>
          {
            // this.state.hasVoted ? <h1>{this.state.voteResult}</h1> :
            this.state.hasVoted ?
              <Button.Group>
                <Button
                  disabled={true}
                  // primary={true}
                  color={this.state.resultButtonColor}
                  content={this.state.voteResult}
                  icon={this.state.currentVoteIcon}
                  size='huge'
                />
                <Button
                  color="instagram"
                  content="Check Result"
                  onClick={this.handleVoteResult}
                  size='huge'
                />
              </Button.Group>
            :
              <InputPetitionID onInputChange={this.handleInputChange}>
                <Button.Group>
                  <Button
                    icon="thumbs up"
                    color="green"
                    onClick={this.handleVoteYes}
                    disabled={this.state.petitionID === null}
                    size='huge'
                  />
                  <Button
                    icon="thumbs down"
                    color="red"
                    onClick={this.handleVoteNo}
                    disabled={this.state.petitionID === null}
                    size='huge'
                  />
                </Button.Group>
              </InputPetitionID>
          }
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
