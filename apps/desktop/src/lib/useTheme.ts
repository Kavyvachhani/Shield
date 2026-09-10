/**
 * The chosen colour theme, remembered across launches.
 *
 * Dark is the default because this tool is used in long sessions alongside
 * terminals and editors. Light is not a token swap bolted on afterwards: both
 * palettes are defined in full in the stylesheet, because a severity colour
 * tuned for navy is unreadable on paper and a report gets reviewed in daylight.
 *
 * Lives here rather than beside `ThemeToggle` so that the component module
 * exports only components — a module mixing the two breaks React Fast Refresh,
 * which reloads the whole module and loses state on every save.
 */

import { useCallback, useEffect, useState } from 'react';

export type Theme = 'dark' | 'light';

const THEME_KEY = 'sentinel.theme';

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const saved = localStorage.getItem(THEME_KEY);
      if (saved === 'light' || saved === 'dark') return saved;
    } catch {
      // A webview with storage disabled must still render.
    }
    return 'dark';
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      // Not remembering the choice is a smaller failure than not applying it.
    }
  }, [theme]);

  const toggle = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), []);
  return [theme, toggle];
}
