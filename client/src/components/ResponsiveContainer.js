import PropTypes from 'prop-types';
import React, { Component } from 'react';
import {
  Button,
  Container,
  Divider,
  Grid,
  Header,
  Icon,
  Image,
  List,
  Menu,
  Responsive,
  Segment,
  Sidebar,
  Visibility,
} from 'semantic-ui-react';
import CredRequester from './MainView/CredRequester';


const HomepageHeading = props => (
  <Container text>
    <Header
      as='h1'
      content='Coconut E-Petition'
      inverted
      style={{
        fontSize: '4em',
        fontWeight: 'normal',
        marginBottom: '1cm',
        marginTop: '1em',
      }}
    />
    {/* <Header
      as='h2'
      content='Do whatever you want when you want to.'
      inverted
      style={{
        fontSize: '1.7em',
        fontWeight: 'normal',
        marginTop: '0.5em',
      }}
    /> */}
    <CredRequester
      ElGamalSK={props.ElGamalSK}
      ElGamalPK={props.ElGamalPK}
      // sk_client will be required to sign requests to SAs, but is NOT sent:
      sk_client={props.sk_client}
      pk_client={props.pk_client}
      handleRandomize={props.handleRandomize}
      handleCredForSpend={props.handleCredForSpend}
      randomizeDisabled={props.randomizeDisabled}
    />
  </Container>
)

HomepageHeading.propTypes = {
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
  pk_client: PropTypes.array.isRequired,
  handleRandomize: PropTypes.func.isRequired,
  handleCredForSpend: PropTypes.func.isRequired,
  randomizeDisabled: PropTypes.bool.isRequired,
}

/* Heads up!
 * Neither Semantic UI nor Semantic UI React offer a responsive navbar, however, it can be implemented easily.
 * It can be more complicated, but you can create really flexible markup.
 */
class ResponsiveContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {};
  }

  hideFixedMenu = () => this.setState({ fixed: false })
  showFixedMenu = () => this.setState({ fixed: true })

  render() {
    const { children } = this.props;
    const { fixed } = this.state;

    return (
      <Responsive minWidth={Responsive.onlyTablet.minWidth}>
        <Visibility
          once={false}
          onBottomPassed={this.showFixedMenu}
          onBottomPassedReverse={this.hideFixedMenu}
        >
          <Segment
            inverted
            textAlign='center'
            style={{ minHeight: 350, padding: '1em 0em' }}
            vertical
          >
            <Menu
              fixed={fixed ? 'top' : null}
              inverted={!fixed}
              pointing={!fixed}
              secondary={!fixed}
              size='large'
            >
              <Container>
                <Menu.Item as='a' active>
                  Home
                </Menu.Item>
                <Menu.Item as='a' href="https://arxiv.org/pdf/1802.07344.pdf">Coconut Paper</Menu.Item>
                <Menu.Item as='a' href="https://github.com/jadwahab">GitHub Repo</Menu.Item>
                <Menu.Item as='a' href="mailto:jadwahab@gmail.com?Subject=Hello">Contact</Menu.Item>
                {/* <Menu.Item position='right'>
                  <Button as='a' inverted={!fixed}>
                    Log in
                  </Button>
                  <Button as='a' inverted={!fixed} primary={fixed} style={{ marginLeft: '0.5em' }}>
                    Sign Up
                  </Button>
                </Menu.Item> */}
              </Container>
            </Menu>
            <HomepageHeading
              ElGamalSK={this.props.ElGamalSK}
              ElGamalPK={this.props.ElGamalPK}
              // sk_client will be required to sign requests to SAs, but is NOT sent:
              sk_client={this.props.sk_client}
              pk_client={this.props.pk_client}
              handleRandomize={this.props.handleRandomize}
              handleCredForSpend={this.props.handleCredForSpend}
              randomizeDisabled={this.props.randomizeDisabled}
            />
          </Segment>
        </Visibility>

        {children}

      </Responsive>
    )
  }
}

ResponsiveContainer.propTypes = {
  children: PropTypes.node,
  ElGamalSK: PropTypes.object.isRequired,
  ElGamalPK: PropTypes.object.isRequired,
  sk_client: PropTypes.array.isRequired,
  pk_client: PropTypes.array.isRequired,
  handleRandomize: PropTypes.func.isRequired,
  handleCredForSpend: PropTypes.func.isRequired,
  randomizeDisabled: PropTypes.bool.isRequired,
}

export default ResponsiveContainer;
