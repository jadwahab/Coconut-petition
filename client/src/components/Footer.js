import React from 'react';
import { Segment, Container, Icon, Divider } from 'semantic-ui-react';

const Footer = () => (
  <Segment
    inverted
    vertical
    style={{ margin: '5em 0em 0em', padding: '2em 0em' }}
  >
    <Container textAlign="center">
      <Divider inverted section />
      <h5>Created by Jędrzej Stuczyński </h5>
      <Container
        style={{ color: '#ffffff' }}
        as="a"
        href="https://github.com/jstuczyn"
      >
        <Icon
          name="github"
          size="huge"
          link
        />
      </Container>
    </Container>
  </Segment>
);

export default Footer;
