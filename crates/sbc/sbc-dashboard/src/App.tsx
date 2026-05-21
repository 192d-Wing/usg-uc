import { useState } from 'react';
import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';
import AppLayout from '@cloudscape-design/components/app-layout';
import TopNavigation from '@cloudscape-design/components/top-navigation';
import { Mode } from '@cloudscape-design/global-styles';

import { Sidebar } from './components/Sidebar';
import { getStoredMode, persistMode } from './theme';
import { Dashboard } from './pages/Dashboard';
import { Phones } from './pages/Phones';
import { PhoneDetail } from './pages/PhoneDetail';
import { Trunkgroups } from './pages/Trunkgroups';
import { Users } from './pages/Users';
import { Registrations } from './pages/Registrations';
import { Directory } from './pages/Directory';
import { Partitions } from './pages/Partitions';
import { CallingSearchSpaces } from './pages/CallingSearchSpaces';
import { RoutePatterns } from './pages/RoutePatterns';
import { RouteLists } from './pages/RouteLists';
import { Cdrs } from './pages/Cdrs';
import { CallLadder } from './pages/CallLadder';

export function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>(getStoredMode());

  const toggleTheme = () => {
    const next = mode === Mode.Dark ? Mode.Light : Mode.Dark;
    setMode(next);
    persistMode(next);
  };

  return (
    <>
      <TopNavigation
        identity={{
          href: '/',
          title: 'USG SBC',
          onFollow: (e) => {
            e.preventDefault();
            navigate('/dashboard');
          },
        }}
        utilities={[
          {
            type: 'button',
            text: mode === Mode.Dark ? 'Light mode' : 'Dark mode',
            ariaLabel: 'Toggle color theme',
            onClick: toggleTheme,
          },
        ]}
      />
      <AppLayout
        navigation={<Sidebar activePath={location.pathname} />}
        toolsHide
        contentType="default"
        content={
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/users" element={<Users />} />
            <Route path="/phones" element={<Phones />} />
            <Route path="/phones/:id" element={<PhoneDetail />} />
            <Route path="/registrations" element={<Registrations />} />
            <Route path="/directory" element={<Directory />} />
            <Route path="/partitions" element={<Partitions />} />
            <Route path="/css" element={<CallingSearchSpaces />} />
            <Route path="/routepatterns" element={<RoutePatterns />} />
            <Route path="/routelists" element={<RouteLists />} />
            <Route path="/trunkgroups" element={<Trunkgroups />} />
            <Route path="/cdrs" element={<Cdrs />} />
            <Route path="/call-ladder" element={<CallLadder />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        }
      />
    </>
  );
}
