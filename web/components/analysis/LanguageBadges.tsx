'use client'

const LANGUAGES = [
  { name: 'Python',     ext: '.py',   color: '#3B82F6' },
  { name: 'JavaScript', ext: '.js',   color: '#EAB308' },
  { name: 'TypeScript', ext: '.ts',   color: '#3B82F6' },
  { name: 'React',      ext: '.jsx',  color: '#06B6D4' },
  { name: 'React TS',   ext: '.tsx',  color: '#06B6D4' },
  { name: 'Java',       ext: '.java', color: '#F97316' },
  { name: 'Go',         ext: '.go',   color: '#00ADD8' },
  { name: 'Rust',       ext: '.rs',   color: '#EF4444' },
  { name: 'Ruby',       ext: '.rb',   color: '#DC2626' },
  { name: 'PHP',        ext: '.php',  color: '#A855F7' },
]

export function LanguageBadges() {
  return (
    <div className="flex flex-wrap gap-2 my-4">
      {LANGUAGES.map(({ name, ext, color }) => (
        <span
          key={ext}
          className="flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-medium"
          style={{
            borderColor: `${color}55`,
            backgroundColor: `${color}11`,
            color,
          }}
        >
          <span className="font-mono text-[10px] opacity-70">{ext}</span>
          {name}
        </span>
      ))}
    </div>
  )
}
