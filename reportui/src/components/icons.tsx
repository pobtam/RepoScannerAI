/**
 * The icon set: simple 1.75px line icons on a 24-unit grid, drawn in
 * currentColor so they take the colour of the text beside them.
 *
 * Icons are decoration next to a text label, never a label on their own, so
 * every one is aria-hidden.
 */
import type { ReactNode } from 'react';

function Svg({ children, size = 18 }: { children: ReactNode; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

export const icons = {
  overview: (
    <Svg>
      <rect x="3" y="3" width="7.5" height="9" rx="2" />
      <rect x="13.5" y="3" width="7.5" height="5.5" rx="2" />
      <rect x="13.5" y="11.5" width="7.5" height="9.5" rx="2" />
      <rect x="3" y="15" width="7.5" height="6" rx="2" />
    </Svg>
  ),
  findings: (
    <Svg>
      <path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6L12 3z" />
      <path d="M12 8.5v4" />
      <path d="M12 16h.01" />
    </Svg>
  ),
  repos: (
    <Svg>
      <path d="M4 5.5A2.5 2.5 0 016.5 3H19v15H6.5A2.5 2.5 0 004 20.5v-15z" />
      <path d="M4 20.5A2.5 2.5 0 006.5 23H19v-5" />
      <path d="M9 8h6" />
    </Svg>
  ),
  coverage: (
    <Svg>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 12l5.5-5.5" />
    </Svg>
  ),
  history: (
    <Svg>
      <path d="M3.5 12a8.5 8.5 0 102.5-6" />
      <path d="M3 3.5V8h4.5" />
      <path d="M12 7.5V12l3 2" />
    </Svg>
  ),
  waves: (
    <Svg>
      <path d="M2.5 8c2 0 2-2 4-2s2 2 4 2 2-2 4-2 2 2 4 2 2-2 3-2" />
      <path d="M2.5 13c2 0 2-2 4-2s2 2 4 2 2-2 4-2 2 2 4 2 2-2 3-2" />
      <path d="M2.5 18c2 0 2-2 4-2s2 2 4 2 2-2 4-2 2 2 4 2 2-2 3-2" />
    </Svg>
  ),
  reports: (
    <Svg>
      <path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z" />
      <path d="M14 3v5h5" />
      <path d="M9 13h6M9 17h4" />
    </Svg>
  ),
  github: (
    <Svg>
      <circle cx="6" cy="6" r="2.5" />
      <circle cx="6" cy="18" r="2.5" />
      <circle cx="18" cy="9" r="2.5" />
      <path d="M6 8.5v7" />
      <path d="M18 11.5c0 3-3 3.5-6 3.5H8.3" />
    </Svg>
  ),
  ai: (
    <Svg>
      <rect x="5" y="5" width="14" height="14" rx="3" />
      <path d="M9 9h6v6H9z" />
      <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" />
    </Svg>
  ),
  shield: (
    <Svg size={18}>
      <path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6L12 3z" />
      <path d="M9 12l2 2 4-4" />
    </Svg>
  ),
  menu: (
    <Svg size={20}>
      <path d="M4 7h16M4 12h16M4 17h16" />
    </Svg>
  ),
  rows: (
    <Svg size={15}>
      <path d="M4 6h16M4 12h16M4 18h16" />
    </Svg>
  ),
  theme: (
    <Svg size={15}>
      <path d="M20 14.5A8.5 8.5 0 019.5 4a8.5 8.5 0 1010.5 10.5z" />
    </Svg>
  ),
};
