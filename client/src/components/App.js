import React from 'react';
import MainView from './MainView';
import styles from './App.style';
import TopMenu from './TopMenu';
import Footer from './Footer';
import ServerStatuses from './ServerStatuses';

const App = () => (
  <div style={styles.siteStyle}>
    <TopMenu />

    <div style={styles.siteContentStyle}>

      <MainView />
      <ServerStatuses />

    </div>

    <Footer />
  </div>
);

export default App;
