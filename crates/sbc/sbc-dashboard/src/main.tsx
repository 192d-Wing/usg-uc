import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

// Cloudscape global styles — must be imported before any Cloudscape components
// so its design tokens / font stack get applied to the document.
import '@cloudscape-design/global-styles/index.css';
import { applyMode } from '@cloudscape-design/global-styles';

import { App } from './App';
import { getStoredMode } from './theme';

applyMode(getStoredMode());

const root = document.getElementById('root');
if (!root) {
  throw new Error('Missing #root element in index.html');
}

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
