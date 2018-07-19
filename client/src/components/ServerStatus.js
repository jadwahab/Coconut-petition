import React from 'react';
import PropTypes from 'prop-types';
import { Table, Header, Icon } from 'semantic-ui-react';
import styles from './ServerStatus.style';
import { SERVER_STATUS, SERVER_TYPES, DEBUG } from '../config';
import { publicKeys } from '../cache';
import { getSigningAuthorityPublicKey, getPublicKey } from '../utils/api';

const ServerStatusInfo = (props) => {
  switch (props.status) {
    case SERVER_STATUS.alive:
      return (
        <div>
          <Icon name="checkmark" color="green" size="large" />
          <p style={styles.statusStyle}>{props.status}</p>
        </div>
      );

    case SERVER_STATUS.loading:
      return (
        <div>
          <Icon name="circle notched" loading size="large" />
          <p style={styles.statusStyle}>{props.status}</p>
        </div>
      );

    case SERVER_STATUS.down:
    default:
      return (
        <div>
          <Icon name="remove" color="red" size="large" />
          <p style={styles.statusStyle}>{props.status}</p>
        </div>
      );
  }
};

ServerStatusInfo.propTypes = {
  status: PropTypes.string.isRequired,
};


class ServerStatus extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      status: SERVER_STATUS.loading,
    };
  }

  async componentDidMount() {
    await this.checkServerStatus();
  }

  checkServerStatus = async () => {
    // get publicKeys of all servers since we will need all of them
    // make a call regardless if anything is cached (it is only done on component load)
    // it will to some extent help with stale entries
    if (DEBUG) {
      console.log(`Getting Public Key of ${this.props.address}...`);
    }
    let publicKey;
    if (this.props.type === SERVER_TYPES.signing) {
      publicKey = await getSigningAuthorityPublicKey(this.props.address);
    } else {
      publicKey = await getPublicKey(this.props.address);
    }
    publicKeys[this.props.address] = publicKey;
    // call failed
    if (publicKeys[this.props.address] == null || publicKeys[this.props.address].length <= 0) {
      this.setState({ status: SERVER_STATUS.down });
    } else {
      this.setState({ status: SERVER_STATUS.alive });
    }
  };

  render() {
    return (
      <Table.Row>
        <Table.Cell>
          <Header as="h4">
            <Header.Content>
              {this.props.address}
              <Header.Subheader>{this.props.type}</Header.Subheader>
            </Header.Content>
          </Header>
        </Table.Cell>
        <Table.Cell>
          <ServerStatusInfo status={this.state.status} />
        </Table.Cell>
      </Table.Row>
    );
  }
}


ServerStatus.propTypes = {
  address: PropTypes.string.isRequired,
  type: PropTypes.string.isRequired,
};

export default ServerStatus;
