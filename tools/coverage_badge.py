"""Write a measured statement-coverage SVG from pytest-cov JSON (no guessed percent)."""
import json
from pathlib import Path

report = json.loads(Path('coverage.json').read_text())
percent = report['totals']['percent_covered']
label = f'{percent:.1f}%'
color = '#22863a' if percent >= 80 else '#b08800'
svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="160" height="24" role="img" aria-label="statement coverage {label}">
<rect width="160" height="24" rx="4" fill="#555"/><path d="M100 0h56a4 4 0 0 1 4 4v16a4 4 0 0 1-4 4h-56z" fill="{color}"/>
<g fill="white" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle"><text x="50" y="16">coverage</text><text x="130" y="16">{label}</text></g></svg>'''
Path('docs/portfolio').mkdir(parents=True, exist_ok=True)
Path('docs/portfolio/coverage.svg').write_text(svg + '\n')
print(f'Measured statement coverage: {label}')
