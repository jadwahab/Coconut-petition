import React from 'react';
import { Container, Table, Header, Segment } from 'semantic-ui-react';
import { signingServers, petitionOwner, issuer, SERVER_TYPES, DEBUG } from '../config';
import ServerStatus from './ServerStatuses/ServerStatus';
import ResetCacheButton from './ServerStatuses/ResetCacheButton';
import { publicKeys } from '../cache';

class ServerStatuses extends React.Component {
  constructor() {
    super();
    this.state = {
      keyPrefix: '0',
    };
  }

  buttonCallback = () => {
    Object.keys(publicKeys).map((key) => { publicKeys[key] = null; return null; });
    const keyPrefix = this.state.keyPrefix === '0' ? '1' : '0';
    this.setState({ keyPrefix });
  };

  render() {
    return (
      <div>
        <Segment style={{ padding: '2em 0em' }} vertical>
          <Container textAlign="center" text>
            <Header
              as="h2"
              textAlign="center"
              content="Status of Servers"
            />
            <Table celled size="small">
              <Table.Header>
                <Table.Row>
                  <Table.HeaderCell>Server</Table.HeaderCell>
                  <Table.HeaderCell>Status</Table.HeaderCell>
                </Table.Row>
              </Table.Header>

              <Table.Body>
                {signingServers.map(server => (
                  <ServerStatus
                    key={this.state.keyPrefix + server}
                    address={server}
                    type={SERVER_TYPES.signing}
                  />
                ))}
                <ServerStatus
                  key={this.state.keyPrefix + petitionOwner}
                  address={petitionOwner}
                  type={SERVER_TYPES.petitionOwner}
                />

                {/* <ServerStatus
                  key={this.state.keyPrefix + issuer}
                  address={issuer}
                  type={SERVER_TYPES.issuer}
                /> */}
              </Table.Body>

            </Table>
          </Container>
        </Segment>
        {DEBUG &&
          <ResetCacheButton onClickCallback={this.buttonCallback} />
        }
      </div>
    );
  }
}

export default ServerStatuses;
