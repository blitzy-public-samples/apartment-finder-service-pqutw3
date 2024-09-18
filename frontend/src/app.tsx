import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Provider } from 'react-redux';
import NavBar from './components/NavBar';
import HomePage from './pages/HomePage';
import SearchResultsPage from './pages/SearchResultsPage';
import ListingDetailPage from './pages/ListingDetailPage';
import UserDashboardPage from './pages/UserDashboardPage';
import SubscriptionPage from './pages/SubscriptionPage';
import { store } from './store';

const App: React.FC = () => {
  return (
    <Provider store={store}>
      <BrowserRouter>
        <div className="app">
          <NavBar />
          <main>
            <Routes>
              <Route path="/" element={<HomePage />} />
              <Route path="/search" element={<SearchResultsPage />} />
              <Route path="/listing/:id" element={<ListingDetailPage />} />
              <Route path="/dashboard" element={<UserDashboardPage />} />
              <Route path="/subscription" element={<SubscriptionPage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </Provider>
  );
};

export default App;