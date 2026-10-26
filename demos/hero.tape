# VHS tape for the Break Anything hero GIF.  Render from repo root:  vhs demos/hero.tape
Output docs/assets/hero.gif

Set Theme "Catppuccin Mocha"
Set FontSize 20
Set Width 1120
Set Height 700
Set Padding 26
Set Margin 42
Set MarginFill "#6C5CE7"
Set WindowBar Colorful
Set BorderRadius 12
Set TypingSpeed 34ms

# --- hidden setup: brk wrapper, proxy for secrets' nothing, build git-history demo repo ---
Hide
Type 'brk(){ bash demos/hero-brk.sh "$@"; }' Enter
Type "bash demos/hero-setup.sh" Enter
Type "clear" Enter
Show

Sleep 500ms
Type "brk deps demos/sample-npm" Enter
Sleep 2600ms

Type "brk secrets /tmp/brk-hero --history" Enter
Sleep 2800ms

Type "# find -> prove -> fix      npx break-anything"
Sleep 2800ms
