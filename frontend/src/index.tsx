import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'react-redux';
import { PayPalScriptProvider } from '@paypal/react-paypal-js';
import App from './app';
import store from './store';

const PAYPAL_CLIENT_ID = process.env.REACT_APP_PAYPAL_CLIENT_ID;

const renderApp = () => {
  const rootElement = document.getElementById('root');
  
  if (!rootElement) {
    console.error('Root element not found');
    return;
  }

  ReactDOM.render(
    <React.StrictMode>
      <Provider store={store}>
        <PayPalScriptProvider options={{ 'client-id': PAYPAL_CLIENT_ID }}>
          <App />
        </PayPalScriptProvider>
      </Provider>
    </React.StrictMode>,
    rootElement
  );
};

renderApp();