import React from 'react';
import { Grid, Segment, Header } from 'semantic-ui-react';
import CoinRequester from './CoinRequester';
import CoinListDisplayer from './CoinListDisplayer';
import { params, DEBUG, DETAILED_DEBUG, issuer, ctx } from '../config';
import ElGamal from '../../lib/ElGamal';

class MainView extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      coins: [],
      ElGamalSK: null,
      ElGamalPK: null,
      sk_client: null,
      pk_client: null,
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



  render() {
    return (
      <Segment style={{ padding: '8em 0em' }} vertical>
        <Header
          as="h2"
          color="teal"
          textAlign="center"
          content="Get issued your credential (by separate issuer entity)"
        />
        <Grid>
          <Grid.Row centered={true}>
            <CoinRequester
              ElGamalSK={this.state.ElGamalSK}
              ElGamalPK={this.state.ElGamalPK}
              sk_client={this.state.sk_client} // will be required to sign requests to SAs, but is NOT sent
              pk_client={this.state.pk_client}
            />
          </Grid.Row>

          <Grid.Row centered={true}>
            <CoinListDisplayer
              coins={this.state.coins}
              ElGamalSK={this.state.ElGamalSK}
              ElGamalPK={this.state.ElGamalPK}
              sk_client={this.state.sk_client} // will be required to sign requests to SAs, but is NOT sent
            />
          </Grid.Row>
        </Grid>
      </Segment>
    );
  }
}

export default MainView;
