import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, ChevronLeft, ChevronRight, User, LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useTheme } from './darkmode/ThemeProvider';
import { MinimalThemeToggle } from './darkmode/ThemeToggle';

const Sidebar = ({ navigationItems, collapsed, onToggleCollapse, currentUser }) => {
  const location = useLocation();
  const { theme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <div className={`
      fixed left-0 top-0 h-full transition-all duration-300 z-50
      ${collapsed ? 'w-16' : 'w-64'}
      ${isDark 
        ? 'bg-zinc-900 border-zinc-800' 
        : 'bg-white border-gray-200'
      }
      border-r
    `}>
      {/* Header */}
      <div className={`
        flex items-center justify-between p-4 
        ${isDark ? 'border-zinc-800' : 'border-gray-200'}
        border-b
      `}>
        <div className={`flex items-center space-x-3 ${collapsed ? 'justify-center' : ''}`}>
          <div className="flex items-center justify-center w-8 h-8 bg-blue-600 rounded-lg shadow-lg">
            <Shield className="w-5 h-5 text-white" />
          </div>
          {!collapsed && (
            <div>
              <h1 className={`
                text-lg font-bold transition-colors
                ${isDark ? 'text-zinc-100' : 'text-gray-900'}
              `}>
                AI Guardian
              </h1>
              <p className={`
                text-xs transition-colors
                ${isDark ? 'text-zinc-400' : 'text-gray-500'}
              `}>
                Cybersecurity Dashboard v4.2
              </p>
            </div>
          )}
        </div>
        
        <div className="flex items-center space-x-1">
          {/* Theme Toggle */}
          {!collapsed && (
            <MinimalThemeToggle className="mr-1" />
          )}
          
          {/* Collapse Toggle */}
          <Button
            variant="ghost"
            size="sm"
            onClick={onToggleCollapse}
            className={`
              p-1 transition-colors
              ${isDark 
                ? 'hover:bg-zinc-800 text-zinc-400 hover:text-zinc-100' 
                : 'hover:bg-gray-100 text-gray-600 hover:text-gray-900'
              }
            `}
          >
            {collapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </Button>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4">
        <ul className="space-y-2">
          {navigationItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            
            return (
              <li key={item.id}>
                <Link
                  to={item.path}
                  className={`
                    flex items-center space-x-3 px-3 py-2 rounded-lg transition-all duration-200
                    ${collapsed ? 'justify-center' : ''}
                    ${isActive
                      ? isDark
                        ? 'bg-zinc-800 text-blue-400 border border-zinc-700 shadow-sm'
                        : 'bg-blue-50 text-blue-700 border border-blue-200 shadow-sm'
                      : isDark
                        ? 'text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100'
                        : 'text-gray-700 hover:bg-gray-100 hover:text-gray-900'
                    }
                    group
                  `}
                  title={collapsed ? item.label : ''}
                >
                  <Icon className={`
                    w-5 h-5 transition-colors
                    ${isActive 
                      ? isDark 
                        ? 'text-blue-400' 
                        : 'text-blue-700'
                      : isDark 
                        ? 'text-zinc-400 group-hover:text-zinc-200' 
                        : 'text-gray-500 group-hover:text-gray-700'
                    }
                  `} />
                  {!collapsed && (
                    <span className={`
                      font-medium transition-colors
                      ${isActive 
                        ? isDark 
                          ? 'text-blue-400' 
                          : 'text-blue-700'
                        : isDark 
                          ? 'text-zinc-300 group-hover:text-zinc-100' 
                          : 'text-gray-700 group-hover:text-gray-900'
                      }
                    `}>
                      {item.label}
                    </span>
                  )}
                  
                  {/* Active indicator */}
                  {isActive && (
                    <div className={`
                      absolute right-0 w-1 h-6 rounded-l-full
                      ${isDark ? 'bg-blue-400' : 'bg-blue-600'}
                    `} />
                  )}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Theme Toggle for Collapsed State */}
      {collapsed && (
        <div className="px-4 pb-2">
          <div className="flex justify-center">
            <MinimalThemeToggle />
          </div>
        </div>
      )}

      {/* User Profile */}
      <div className={`
        ${isDark ? 'border-zinc-800' : 'border-gray-200'}
        border-t p-4
      `}>
        {!collapsed ? (
          <div className="space-y-3">
            <div className="flex items-center space-x-3">
              <div className={`
                flex items-center justify-center w-8 h-8 rounded-full
                ${isDark ? 'bg-zinc-700' : 'bg-gray-300'}
              `}>
                <User className={`
                  w-4 h-4
                  ${isDark ? 'text-zinc-300' : 'text-gray-600'}
                `} />
              </div>
              <div className="flex-1 min-w-0">
                <p className={`
                  text-sm font-medium truncate transition-colors
                  ${isDark ? 'text-zinc-100' : 'text-gray-900'}
                `}>
                  {currentUser.name}
                </p>
                <p className={`
                  text-xs truncate transition-colors
                  ${isDark ? 'text-zinc-400' : 'text-gray-500'}
                `}>
                  {currentUser.email}
                </p>
                <p className={`
                  text-xs capitalize font-medium transition-colors
                  ${isDark ? 'text-zinc-300' : 'text-gray-600'}
                `}>
                  {currentUser.role}
                </p>
              </div>
            </div>
            
            <Button
              variant="ghost"
              size="sm"
              className={`
                w-full justify-start transition-colors
                ${isDark 
                  ? 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800' 
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }
              `}
            >
              <LogOut className="w-4 h-4 mr-2" />
              Sign Out
            </Button>
          </div>
        ) : (
          <div className="flex justify-center">
            <Button
              variant="ghost"
              size="sm"
              className={`
                p-2 transition-colors
                ${isDark 
                  ? 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800' 
                  : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
                }
              `}
              title={`${currentUser.name} - Sign Out`}
            >
              <User className="w-4 h-4" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};

export default Sidebar;

