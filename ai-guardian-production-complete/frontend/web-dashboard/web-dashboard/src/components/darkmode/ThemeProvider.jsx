"use client"

import React, { createContext, useContext, useEffect, useState } from 'react';

/**
 * Theme Configuration with Zinc Color Palette
 */
const THEME_CONFIG = {
  light: {
    // Light mode colors (minimal for now, focus on dark mode)
    primary: '#ffffff',
    secondary: '#f8fafc',
    background: '#ffffff',
    foreground: '#0f172a',
    muted: '#f1f5f9',
    border: '#e2e8f0',
    accent: '#0ea5e9',
  },
  dark: {
    // Dark mode with Zinc palette as specified in v4.2.0 plan
    primary: '#09090b',      // zinc-950
    secondary: '#18181b',    // zinc-900  
    tertiary: '#27272a',     // zinc-800
    background: '#09090b',   // zinc-950
    backgroundSecondary: '#18181b', // zinc-900
    backgroundTertiary: '#27272a',  // zinc-800
    foreground: '#fafafa',   // zinc-50
    foregroundSecondary: '#a1a1aa', // zinc-400
    foregroundMuted: '#71717a',     // zinc-500
    border: '#3f3f46',       // zinc-700
    borderLight: '#52525b',  // zinc-600
    accent: '#0ea5e9',       // sky-500
    success: '#10b981',      // emerald-500
    warning: '#f59e0b',      // amber-500
    error: '#ef4444',        // red-500
    info: '#8b5cf6',         // violet-500
  },
};

/**
 * CSS Custom Properties for Theme
 */
const generateCSSVariables = (theme) => {
  return Object.entries(theme).reduce((css, [key, value]) => {
    const cssKey = key.replace(/([A-Z])/g, '-$1').toLowerCase();
    return css + `--color-${cssKey}: ${value};\n`;
  }, '');
};

/**
 * Theme Context
 */
const ThemeContext = createContext({
  theme: 'dark',
  toggleTheme: () => {},
  colors: THEME_CONFIG.dark,
  setTheme: () => {},
});

/**
 * Theme Provider Component
 */
export const ThemeProvider = ({ children, defaultTheme = 'dark' }) => {
  const [theme, setTheme] = useState(defaultTheme);
  const [mounted, setMounted] = useState(false);

  // Initialize theme from localStorage on mount
  useEffect(() => {
    const savedTheme = localStorage.getItem('ai-guardian-theme');
    if (savedTheme && (savedTheme === 'light' || savedTheme === 'dark')) {
      setTheme(savedTheme);
    }
    setMounted(true);
  }, []);

  // Apply theme to document and save to localStorage
  useEffect(() => {
    if (!mounted) return;

    const root = document.documentElement;
    const colors = THEME_CONFIG[theme];
    
    // Apply CSS custom properties
    const cssVariables = generateCSSVariables(colors);
    const styleSheet = document.createElement('style');
    styleSheet.textContent = `:root { ${cssVariables} }`;
    
    // Remove existing theme stylesheets
    const existingThemeStyles = document.querySelectorAll('style[data-theme]');
    existingThemeStyles.forEach(style => style.remove());
    
    // Add new theme stylesheet
    styleSheet.setAttribute('data-theme', theme);
    document.head.appendChild(styleSheet);
    
    // Apply theme class to html element
    root.classList.remove('light', 'dark');
    root.classList.add(theme);
    
    // Save theme preference
    localStorage.setItem('ai-guardian-theme', theme);
    
    // Apply Tailwind dark mode class
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme, mounted]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  const value = {
    theme,
    toggleTheme,
    setTheme,
    colors: THEME_CONFIG[theme],
    mounted,
  };

  // Prevent hydration mismatch by not rendering until mounted
  if (!mounted) {
    return <div className="animate-pulse bg-zinc-950 min-h-screen" />;
  }

  return (
    <ThemeContext.Provider value={value}>
      <div className={`theme-${theme} transition-colors duration-300`}>
        {children}
      </div>
    </ThemeContext.Provider>
  );
};

/**
 * Hook to use theme context
 */
export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

/**
 * Theme Aware Component Wrapper
 */
export const ThemeAware = ({ children, lightClass = '', darkClass = '', className = '' }) => {
  const { theme } = useTheme();
  const themeClass = theme === 'dark' ? darkClass : lightClass;
  
  return (
    <div className={`${className} ${themeClass}`}>
      {children}
    </div>
  );
};

/**
 * Color Utility Functions
 */
export const getThemeColor = (colorKey, fallback = '#000000') => {
  const { colors } = useTheme();
  return colors[colorKey] || fallback;
};

export const isLightTheme = () => {
  const { theme } = useTheme();
  return theme === 'light';
};

export const isDarkTheme = () => {
  const { theme } = useTheme();
  return theme === 'dark';
};

/**
 * CSS-in-JS Theme Styles
 */
export const themeStyles = {
  card: {
    dark: 'border-zinc-800 bg-zinc-900/50 backdrop-blur-sm',
    light: 'border-gray-200 bg-white',
  },
  text: {
    primary: {
      dark: 'text-zinc-50',
      light: 'text-gray-900',
    },
    secondary: {
      dark: 'text-zinc-400',
      light: 'text-gray-600',
    },
    muted: {
      dark: 'text-zinc-500',
      light: 'text-gray-500',
    },
  },
  background: {
    primary: {
      dark: 'bg-zinc-950',
      light: 'bg-white',
    },
    secondary: {
      dark: 'bg-zinc-900',
      light: 'bg-gray-50',
    },
    tertiary: {
      dark: 'bg-zinc-800',
      light: 'bg-gray-100',
    },
  },
  border: {
    default: {
      dark: 'border-zinc-800',
      light: 'border-gray-200',
    },
    light: {
      dark: 'border-zinc-700',
      light: 'border-gray-300',
    },
  },
  input: {
    dark: 'bg-zinc-800 border-zinc-700 text-zinc-100',
    light: 'bg-white border-gray-300 text-gray-900',
  },
  button: {
    primary: {
      dark: 'bg-blue-600 hover:bg-blue-700 text-white',
      light: 'bg-blue-600 hover:bg-blue-700 text-white',
    },
    secondary: {
      dark: 'bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border-zinc-700',
      light: 'bg-gray-100 hover:bg-gray-200 text-gray-900 border-gray-300',
    },
  },
};

/**
 * Theme-aware utility hook for getting classes
 */
export const useThemeClasses = () => {
  const { theme } = useTheme();
  
  const getThemeClass = (styles, fallback = '') => {
    if (typeof styles === 'string') return styles;
    return styles[theme] || fallback;
  };
  
  return { getThemeClass, theme };
};

export default ThemeProvider; 