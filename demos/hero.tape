# VHS tape for the Break Anything hero GIF.
# Render: vhs demos/hero.tape   (run from repo root)
Output docs/assets/hero.gif

Set Theme "Dracula"
Set FontSize 17
Set Width 1180
Set Height 820
Set Padding 24
Set TypingSpeed 50ms
Set PlaybackSpeed 1.0

# --- hidden setup: define brk, set proxy, build the git-history demo repo ---
Hide
Type "export HTTPS_PROXY=http://127.0.0.1:7897 HTTP_PROXY=http://127.0.0.1:7897" Enter
Type 'brk(){ node bin/brk.js "$@"; }' Enter
Type "bash demos/hero-setup.sh" Enter
Type "clear" Enter
Show

# --- beat 1: a dependency you forgot, scanned for real ---
Type "# Break Anything — find what's broken before they do" Enter
Sleep 900ms
Type "brk deps demos/sample-npm" Enter
Sleep 13s

# --- beat 2: a secret you thought you deleted ---
Type "# You deleted the key from the code. It's still in your git history." Enter
Sleep 900ms
Type "brk secrets /tmp/brk-hero --history" Enter
Sleep 3500ms

# --- outro ---
Type "# Find -> Prove -> Fix.    npx break-anything" Enter
Sleep 2800ms
