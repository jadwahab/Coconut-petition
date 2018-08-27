import React from 'react';
import { Grid, Segment, Header } from 'semantic-ui-react';
import ServerStatuses from './ServerStatuses';
import ResponsiveContainer from './ResponsiveContainer';
import CredRequester from './MainView/CredRequester';
import VoteListDisplayer from './MainView/VoteListDisplayer';
import { params, DEBUG, DETAILED_DEBUG } from '../config';
import ElGamal from '../../lib/ElGamal';
import CredSig from '../../lib/CredSig';

class MainView extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      randomizedSignatures: [],
      ElGamalSK: null,
      ElGamalPK: null,
      sk_client: null,
      pk_client: null,
      cred_params: null,
      randomizeDisabled: false,
    };
  }

  componentWillMount() {
    // generate ElGamal keypair
    const [sk_elgamal, pk_elgamal] = ElGamal.keygen(params);
    const [G, o, g1, g2, e] = params;

    // due to way ECDSA is implemented, theres no point in storing the other representation,
    // bytes are enough
    const skBytes_client = [];
    const pkBytes_client = [];
    // generate keypair for signing messages
    const sk_client = G.ctx.BIG.randomnum(o, G.rngGen);
    sk_client.toBytes(skBytes_client);
    const pk_client = g1.mul(sk_client);
    pk_client.toBytes(pkBytes_client);

    this.setState({
      ElGamalSK: sk_elgamal,
      ElGamalPK: pk_elgamal,
      sk_client: skBytes_client,
      pk_client: pkBytes_client,
    });

    if (DEBUG) {
      console.log('Generated ElGamal keypair.');
      if (DETAILED_DEBUG) {
        console.log('Keys:', sk_elgamal, pk_elgamal);
      }
      console.log('Generated client keypair.');
      if (DETAILED_DEBUG) {
        console.log('Keys:', skBytes_client, pkBytes_client);
      }
    }
  }


  handleRandomize = (sig) => {
    const randomizedSignature = CredSig.randomize(params, sig);

    /* Not working right for some reason: (consider fixing in future)
    this.setState(prevState => ({
      randomizedSignatures: prevState.randomizedSignatures.concat([randomizedSignature]),
    }));
    */
    /* Messes up with length as seen below with console.logs below:
    console.log(this.state.randomizedSignatures.length);
    console.log(this.state.randomizedSignatures);
    */

    // works but is less elegant:
    const randSigs = this.state.randomizedSignatures;
    randSigs.push(randomizedSignature);
    this.setState({
      randomizedSignatures: randSigs,
      randomizeDisabled: false,
    });

    this.handleRandomizeDisabled(true);

    return randomizedSignature;
  };


  handleCredForSpend = (cred, sk) => {
    const cred_params = { cred: cred, sk: sk };
    this.setState({ cred_params });
  }

  handleRandomizeDisabled = (state) => {
    this.setState({ randomizeDisabled: state });
  }

  render() {
    return (
      <ResponsiveContainer
        ElGamalSK={this.state.ElGamalSK}
        ElGamalPK={this.state.ElGamalPK}
        // sk_client will be required to sign requests to SAs, but is NOT sent:
        sk_client={this.state.sk_client}
        pk_client={this.state.pk_client}
        handleRandomize={this.handleRandomize}
        handleCredForSpend={this.handleCredForSpend}
        randomizeDisabled={this.state.randomizeDisabled}
      >
        <div>
          <Grid>
            {/* <Grid.Row centered={true}>
              <CredRequester
                ElGamalSK={this.state.ElGamalSK}
                ElGamalPK={this.state.ElGamalPK}
                // sk_client will be required to sign requests to SAs, but is NOT sent:
                sk_client={this.state.sk_client}
                pk_client={this.state.pk_client}
                handleRandomize={this.handleRandomize}
                handleCredForSpend={this.handleCredForSpend}
                randomizeDisabled={this.state.randomizeDisabled}
              />
            </Grid.Row> */}

            <Grid.Row centered={true}>
              <VoteListDisplayer
                randomizedSignatures={this.state.randomizedSignatures}
                cred_params={this.state.cred_params}
                handleRandomizeDisabled={this.handleRandomizeDisabled}
              />
            </Grid.Row>
          </Grid>

          <ServerStatuses />
        </div>
      </ResponsiveContainer>

    );
  }
}

export default MainView;
