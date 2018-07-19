import React from 'react';
import { Menu, Container, Icon } from 'semantic-ui-react';

const TopMenu = () => (
  <Menu fixed="top" size="huge" inverted pointing>
    <Container>
      <Menu.Item header>
        Multi-Authority SDC
      </Menu.Item>
      <Menu.Item as="a" active href="#">Home</Menu.Item>
      <Menu.Menu position="right">
        <Menu.Item as="a" href="https://github.com/jstuczyn/Multi-Authority-SDC/">
          <Icon name="github" />
          Repository
        </Menu.Item>
      </Menu.Menu>
    </Container>
  </Menu>
);

export default TopMenu;
