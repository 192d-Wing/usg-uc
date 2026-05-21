import { applyMode, Mode } from '@cloudscape-design/global-styles';

const KEY = 'usg-sbc.theme';

export function getStoredMode(): Mode {
  try {
    return localStorage.getItem(KEY) === 'light' ? Mode.Light : Mode.Dark;
  } catch {
    return Mode.Dark;
  }
}

export function persistMode(mode: Mode): void {
  applyMode(mode);
  try {
    localStorage.setItem(KEY, mode === Mode.Light ? 'light' : 'dark');
  } catch {
    // localStorage unavailable (private mode, etc.) — fall back to runtime-only
  }
}
