import React from 'react';

interface ArgusLogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  showText?: boolean;
}

export const ArgusLogo: React.FC<ArgusLogoProps> = ({
  className = '',
  size = 'md',
  showText = false,
}) => {
  const iconDimensions = {
    sm: 'w-6 h-6',
    md: 'w-8 h-8',
    lg: 'w-10 h-10',
  }[size];

  return (
    <div className={`flex items-center gap-2.5 ${className}`}>
      <div className={`relative ${iconDimensions} flex items-center justify-center shrink-0`}>
        {/* Ambient glow behind icon */}
        <div className="absolute inset-0 bg-emerald-500/20 rounded-lg blur-md" />

        {/* SVG Shield with Cyclops/Argus Eye Aperture */}
        <svg
          viewBox="0 0 36 36"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full relative z-10 drop-shadow-md"
        >
          {/* Hex Shield Border */}
          <path
            d="M18 3L31 8V18C31 26 25 31.5 18 33.5C11 31.5 5 26 5 18V8L18 3Z"
            fill="#0B1322"
            stroke="url(#argus-shield-grad)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Inner Security Eye / Lens Aperture */}
          <circle
            cx="18"
            cy="17"
            r="6"
            stroke="url(#argus-eye-grad)"
            strokeWidth="1.8"
            strokeDasharray="2 1.5"
          />
          <circle cx="18" cy="17" r="2.8" fill="#10B981" />
          <path
            d="M13 17H7M29 17H23M18 11V7M18 27V23"
            stroke="#06B6D4"
            strokeWidth="1.4"
            strokeLinecap="round"
            opacity="0.6"
          />

          <defs>
            <linearGradient id="argus-shield-grad" x1="5" y1="3" x2="31" y2="33.5" gradientUnits="userSpaceOnUse">
              <stop stopColor="#10B981" />
              <stop offset="0.5" stopColor="#06B6D4" />
              <stop offset="1" stopColor="#3B82F6" />
            </linearGradient>
            <linearGradient id="argus-eye-grad" x1="12" y1="11" x2="24" y2="23" gradientUnits="userSpaceOnUse">
              <stop stopColor="#34D399" />
              <stop offset="1" stopColor="#06B6D4" />
            </linearGradient>
          </defs>
        </svg>
      </div>

      {showText && (
        <div className="flex flex-col">
          <div className="flex items-center gap-1.5 leading-none">
            <span className="font-bold tracking-wider text-slate-100 text-lg font-mono">ARGUS</span>
            <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-800/60 font-semibold tracking-wide">
              White-box
            </span>
          </div>
          <span className="text-[11px] text-slate-400 font-normal mt-0.5 tracking-tight">
            OpenCodeReview AI 白盒代码审查
          </span>
        </div>
      )}
    </div>
  );
};
