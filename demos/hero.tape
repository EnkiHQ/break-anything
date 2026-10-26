# VHS tape for the Break Anything hero GIF.  Render from repo root:  vhs demos/hero.tape
Output docs/assets/hero.gif

Set Theme "Catppuccin Mocha"
Set FontSize 20
Set Width 1120
Set Height 760
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

Sleep 400ms
Type "# 12 vulns flagged here. which ones can actually reach me?" Enter
Sleep 1100ms
Type "brk deps demos/sample-npm" Enter
Sleep 3000ms
Type "# ^ only the ones my code really calls. and a key i deleted is still in git:" Enter
Sleep 1100ms
Type "brk secrets /tmp/brk-hero --history" Enter
Sleep 2600ms
Type "# found -> proven -> fixed.      npx break-anything"
Sleep 2600ms
