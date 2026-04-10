# Demo Recording

## What to record

Run this command and record with [vhs](https://github.com/charmbracelet/vhs)
or [asciinema](https://asciinema.org/):

    vibe-guard scan tests/fixtures/vulnerable_app --format terminal

Then capture a screenshot of the GitHub Security tab showing the SARIF
annotations on a pull request.

## Suggested vhs script

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 700

Type "vibe-guard scan tests/fixtures/vulnerable_app"
Enter
Sleep 3s

## Output

Save the GIF to docs/demo.gif and update README.md to reference it:

    ![vibe-guard demo](docs/demo.gif)
