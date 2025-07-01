"use client"

import React from 'react';
import { Moon, Sun } from 'lucide-react';
import { useTheme } from './ThemeProvider';

/**
 * Theme Toggle Component
 * Provides an interactive toggle between light and dark themes
 */
export const ThemeToggle = ({ 
  size = 'default', 
  showLabel = false, 
  variant = 'default',
  className = '' 
}) => {
  const { theme, toggleTheme, mounted } = useTheme();

  // Prevent hydration mismatch
  if (!mounted) {
    return (
      <div className={`
        animate-pulse bg-zinc-800 rounded-lg 
        ${size === 'sm' ? 'w-8 h-8' : size === 'lg' ? 'w-12 h-12' : 'w-10 h-10'}
      `} />
    );
  }

  const isDark = theme === 'dark';

  // Size variants
  const sizeClasses = {
    sm: 'w-8 h-8 text-sm',
    default: 'w-10 h-10',
    lg: 'w-12 h-12 text-lg'
  };

  // Button variant styles
  const buttonVariants = {
    default: `
      ${isDark 
        ? 'bg-zinc-800 hover:bg-zinc-700 border-zinc-700 text-zinc-100' 
        : 'bg-white hover:bg-gray-50 border-gray-300 text-gray-700'
      }
      border transition-all duration-300 ease-in-out
      hover:scale-105 active:scale-95
    `,
    ghost: `
      ${isDark 
        ? 'hover:bg-zinc-800 text-zinc-400 hover:text-zinc-100' 
        : 'hover:bg-gray-100 text-gray-600 hover:text-gray-900'
      }
      transition-all duration-300 ease-in-out
      hover:scale-105 active:scale-95
    `,
    outline: `
      ${isDark 
        ? 'border-zinc-700 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100' 
        : 'border-gray-300 text-gray-600 hover:bg-gray-50 hover:text-gray-900'
      }
      border-2 transition-all duration-300 ease-in-out
      hover:scale-105 active:scale-95
    `
  };

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <button
        onClick={toggleTheme}
        className={`
          ${sizeClasses[size]}
          ${buttonVariants[variant]}
          rounded-lg flex items-center justify-center
          focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
          ${isDark ? 'focus:ring-offset-zinc-900' : 'focus:ring-offset-white'}
          group relative overflow-hidden
        `}
        title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
        aria-label={`Switch to ${isDark ? 'light' : 'dark'} mode`}
      >
        {/* Background gradient animation */}
        <div className={`
          absolute inset-0 transition-opacity duration-500
          ${isDark 
            ? 'bg-gradient-to-br from-zinc-800 to-zinc-900 opacity-0 group-hover:opacity-100' 
            : 'bg-gradient-to-br from-blue-50 to-indigo-50 opacity-0 group-hover:opacity-100'
          }
        `} />
        
        {/* Icon container with rotation animation */}
        <div className="relative z-10 transition-transform duration-500 ease-in-out group-hover:rotate-180">
          {isDark ? (
            <Sun className={`
              ${size === 'sm' ? 'w-4 h-4' : size === 'lg' ? 'w-6 h-6' : 'w-5 h-5'}
              transition-all duration-300 ease-in-out
              text-amber-400 group-hover:text-amber-300
              drop-shadow-sm
            `} />
          ) : (
            <Moon className={`
              ${size === 'sm' ? 'w-4 h-4' : size === 'lg' ? 'w-6 h-6' : 'w-5 h-5'}
              transition-all duration-300 ease-in-out
              text-slate-600 group-hover:text-slate-800
              drop-shadow-sm
            `} />
          )}
        </div>
        
        {/* Ripple effect on click */}
        <div className="absolute inset-0 opacity-0 group-active:opacity-20 transition-opacity duration-150">
          <div className={`
            absolute inset-0 rounded-lg
            ${isDark ? 'bg-zinc-400' : 'bg-gray-400'}
            animate-ping
          `} />
        </div>
      </button>
      
      {/* Optional label */}
      {showLabel && (
        <span className={`
          text-sm font-medium transition-colors duration-300
          ${isDark ? 'text-zinc-400' : 'text-gray-600'}
        `}>
          {isDark ? 'Dark' : 'Light'}
        </span>
      )}
    </div>
  );
};

/**
 * Theme Toggle with Text Label (alternative layout)
 */
export const ThemeToggleWithLabel = ({ className = '' }) => {
  const { theme, toggleTheme, mounted } = useTheme();

  if (!mounted) {
    return <div className="animate-pulse bg-zinc-800 h-10 w-24 rounded-lg" />;
  }

  const isDark = theme === 'dark';

  return (
    <button
      onClick={toggleTheme}
      className={`
        ${className}
        ${isDark 
          ? 'bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border-zinc-700' 
          : 'bg-white hover:bg-gray-50 text-gray-700 border-gray-300'
        }
        px-3 py-2 rounded-lg border
        flex items-center gap-2 text-sm font-medium
        transition-all duration-300 ease-in-out
        hover:scale-105 active:scale-95
        focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
        ${isDark ? 'focus:ring-offset-zinc-900' : 'focus:ring-offset-white'}
      `}
      title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
    >
      {isDark ? (
        <>
          <Sun className="w-4 h-4 text-amber-400" />
          <span>Light</span>
        </>
      ) : (
        <>
          <Moon className="w-4 h-4 text-slate-600" />
          <span>Dark</span>
        </>
      )}
    </button>
  );
};

/**
 * Minimal Theme Toggle (icon only, no border)
 */
export const MinimalThemeToggle = ({ className = '' }) => {
  const { theme, toggleTheme, mounted } = useTheme();

  if (!mounted) {
    return <div className="animate-pulse bg-zinc-800 w-6 h-6 rounded" />;
  }

  const isDark = theme === 'dark';

  return (
    <button
      onClick={toggleTheme}
      className={`
        ${className}
        p-1 rounded transition-all duration-300
        ${isDark 
          ? 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800' 
          : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
        }
        focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
        ${isDark ? 'focus:ring-offset-zinc-900' : 'focus:ring-offset-white'}
      `}
      title={`Switch to ${isDark ? 'light' : 'dark'} mode`}
    >
      {isDark ? (
        <Sun className="w-5 h-5" />
      ) : (
        <Moon className="w-5 h-5" />
      )}
    </button>
  );
};

export default ThemeToggle; 